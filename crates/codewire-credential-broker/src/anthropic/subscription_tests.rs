use codewire_access::{BrokerOperationId, CapabilitySlot, CredentialStatus, ProviderId};
use http::{HeaderName, Method, header};

use super::super::AnthropicApiKeyAdapter;
use super::super::tests::{CLAUDE_BETAS, Lease, claude_headers, reflections};
use super::*;

/// Synthetic only; shaped like a `claude setup-token` value.
const TOKEN: &[u8] = b"sk-ant-oat01-CW_TEST_SUBSCRIPTION_token-_~+/=";
const BODY: &[u8] = br#"{"model":"synthetic-model","max_tokens":64,"messages":[{"role":"user","content":"hello"}],"stream":true,"safeguards":[{"type":"dangerous_tool_use","classifier_context":{"v":1,"permission_mode":"auto"}}]}"#;
/// The beta flags Claude Code 2.1.308 sent in subscription mode
/// (`CLAUDE_CODE_OAUTH_TOKEN`), captured in a run with the same arguments; its
/// other headers were those of [`claude_headers`] apart from
/// `content-length`.
const SUBSCRIPTION_BETAS: &str = "claude-code-20250219,oauth-2025-04-20,\
interleaved-thinking-2025-05-14,thinking-token-count-2026-05-13,context-management-2025-06-27,\
advanced-tool-use-2025-11-20,effort-2025-11-24,dangerous-tool-use-2026-09-03,\
thinking-display-updates-2026-08-18,afk-mode-2026-01-31,extended-cache-ttl-2025-04-11";

fn token_lease() -> Lease {
    Lease::new(CredentialAuthKind::OAuth, TOKEN)
}

fn subscription_headers() -> HeaderMap {
    let mut headers = claude_headers();
    headers.insert(
        "anthropic-beta",
        HeaderValue::from_static(SUBSCRIPTION_BETAS),
    );
    headers
}

fn prepare(
    lease: Lease,
    method: &Method,
    path: &str,
    headers: HeaderMap,
) -> Result<PreparedAnthropicRequest, CredentialBrokerError> {
    let validated = AnthropicApiKeyAdapter::new().unwrap().validate_request(
        method,
        path,
        None,
        headers,
        BODY.to_vec(),
    )?;
    AnthropicSubscriptionTokenAdapter::new()
        .unwrap()
        .prepare_validated(lease, validated)
}

#[test]
fn the_stored_token_replaces_the_guest_bearer_on_any_path() {
    let guest = subscription_headers();
    for (method, path) in [
        (Method::POST, "/v1/messages"),
        (Method::POST, "/v1/messages/count_tokens"),
        (Method::GET, "/api/oauth/usage"),
        (Method::GET, "/api/oauth/profile"),
    ] {
        let (sent_method, target, headers, body, _) =
            prepare(token_lease(), &method, path, guest.clone())
                .unwrap()
                .into_parts();
        assert_eq!(sent_method, method);
        assert_eq!(target.as_str(), format!("https://api.anthropic.com{path}"));
        assert_eq!(body, BODY);
        let mut bearer = b"Bearer ".to_vec();
        bearer.extend_from_slice(TOKEN);
        assert_eq!(headers[header::AUTHORIZATION].as_bytes(), bearer);
        assert_eq!(headers.get_all(header::AUTHORIZATION).iter().count(), 1);
        assert!(!headers.contains_key("x-api-key"));
        assert!(!headers.contains_key("cookie"));
        assert_eq!(headers["anthropic-beta"], SUBSCRIPTION_BETAS);
        for kept in [
            "user-agent",
            "x-app",
            "x-claude-code-session-id",
            "x-stainless-lang",
            "anthropic-version",
        ] {
            assert_eq!(headers.get(kept), guest.get(kept), "{kept}");
        }
    }
}

#[test]
fn the_oauth_beta_is_added_once_and_split_beta_lines_are_joined() {
    let mut without = claude_headers();
    without.remove("anthropic-beta");
    let headers = prepare(token_lease(), &Method::POST, "/v1/messages", without)
        .unwrap()
        .into_parts()
        .2;
    assert_eq!(headers["anthropic-beta"], OAUTH_BETA);

    // A client sending the API-key form's flags to a subscription credential
    // gains the OAuth flag once, at the end.
    let headers = prepare(
        token_lease(),
        &Method::POST,
        "/v1/messages",
        claude_headers(),
    )
    .unwrap()
    .into_parts()
    .2;
    assert_eq!(headers.get_all("anthropic-beta").iter().count(), 1);
    assert_eq!(
        headers["anthropic-beta"],
        format!("{CLAUDE_BETAS},{OAUTH_BETA}")
    );

    let mut split = claude_headers();
    split.remove("anthropic-beta");
    split.append(
        "anthropic-beta",
        HeaderValue::from_static("claude-code-20250219"),
    );
    split.append(
        "anthropic-beta",
        HeaderValue::from_static("dangerous-tool-use-2026-09-03, oauth-2025-04-20"),
    );
    let headers = prepare(token_lease(), &Method::POST, "/v1/messages", split)
        .unwrap()
        .into_parts()
        .2;
    assert_eq!(headers.get_all("anthropic-beta").iter().count(), 1);
    assert_eq!(
        headers["anthropic-beta"],
        "claude-code-20250219,dangerous-tool-use-2026-09-03,oauth-2025-04-20"
    );
}

#[test]
fn every_lease_coordinate_and_the_oauth_kind_are_checked_before_the_token() {
    for case in 0..6 {
        let mut lease = token_lease();
        match case {
            0 => lease.metadata.authentication_kind = CredentialAuthKind::ApiKey,
            1 => lease.metadata.provider = ProviderId::parse("openai").unwrap(),
            2 => lease.metadata.status = CredentialStatus::Revoked,
            3 => lease.grant.capability_slot = CapabilitySlot::parse("codex").unwrap(),
            4 => lease.permission.operation = BrokerOperationId::parse("count-tokens").unwrap(),
            _ => lease.grant.permissions.clear(),
        }
        let accessed = lease.accessed.clone();
        assert_eq!(
            prepare(lease, &Method::POST, "/v1/messages", subscription_headers()).err(),
            Some(CredentialBrokerError::UnsupportedLease),
            "case {case}"
        );
        assert_eq!(accessed.get(), 0, "case {case}");
    }
}

#[test]
fn malformed_empty_and_oversized_tokens_are_closed_value_blind_errors() {
    for material in [
        vec![],
        b"token\ncanary".to_vec(),
        b"token canary".to_vec(),
        vec![0xff],
        vec![b'x'; 1025],
    ] {
        let error = prepare(
            Lease::new(CredentialAuthKind::OAuth, &material),
            &Method::POST,
            "/v1/messages",
            subscription_headers(),
        )
        .err()
        .unwrap();
        assert_eq!(error, CredentialBrokerError::InvalidCredentialMaterial);
        assert!(!format!("{error:?}: {error}").contains("canary"));
    }
}

#[test]
fn token_reflections_are_redacted_in_bodies_and_every_returned_header() {
    for reflection in reflections(TOKEN) {
        let response = prepare(
            token_lease(),
            &Method::POST,
            "/v1/messages",
            subscription_headers(),
        )
        .unwrap()
        .into_parts()
        .4;
        let mut upstream = HeaderMap::new();
        upstream.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("text/event-stream"),
        );
        for name in [
            "request-id",
            "anthropic-ratelimit-unified-5h-utilization",
            "x-new-provider-header",
        ] {
            upstream.insert(
                HeaderName::from_static(name),
                HeaderValue::from_bytes(&reflection).unwrap(),
            );
        }
        let (headers, mut body) = response.begin(&upstream).unwrap();
        for name in [
            "request-id",
            "anthropic-ratelimit-unified-5h-utilization",
            "x-new-provider-header",
        ] {
            assert_eq!(headers[name], "[REDACTED]", "{name}");
        }
        let mut output = body.push(b"data: ").unwrap();
        output.extend(body.push(&reflection).unwrap());
        output.extend(body.finish().unwrap());
        assert_eq!(output, b"data: [REDACTED]");
    }
}
