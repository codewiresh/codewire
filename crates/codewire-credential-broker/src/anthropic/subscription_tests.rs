use std::cell::Cell;
use std::collections::BTreeSet;
use std::rc::Rc;

use base64::{Engine as _, engine::general_purpose::STANDARD};
use codewire_access::{
    AccessProfileId, BrokerOperationId, BrokerRouteId, CapabilitySlot, CredentialId,
    CredentialMetadata, CredentialStatus, DerivedGrant, EnvironmentId, GrantPermission,
    GrantProfile, Owner, OwnerId, Placement, ProviderId,
};
use http::{HeaderName, Method};
use zeroize::Zeroizing;

use super::super::AnthropicApiKeyAdapter;
use super::*;

/// Synthetic only; shaped like a `claude setup-token` value.
const TOKEN: &[u8] = b"sk-ant-oat01-CW_TEST_SUBSCRIPTION_token-_~+/=";
const BODY: &[u8] = br#"{"model":"synthetic-model","max_tokens":64,"messages":[{"role":"user","content":"hello"}],"stream":true}"#;
const USER_AGENT: &str = "claude-cli/2.1.238 (external, sdk-cli)";
const SESSION: &str = "8566fd02-a622-43da-871a-2fa90259b0f9";
/// Claude Code's own `anthropic-beta` features beside [`OAUTH_BETA`].
const CLAUDE_CODE_BETA: &str = "claude-code-20250219";
const THINKING_BETA: &str = "interleaved-thinking-2025-05-14";

/// The `anthropic-beta` value Claude Code 2.1.238 sends in subscription mode.
fn claude_code_betas() -> String {
    [CLAUDE_CODE_BETA, OAUTH_BETA, THINKING_BETA].join(",")
}

struct Lease {
    metadata: CredentialMetadata,
    grant: DerivedGrant,
    permission: GrantPermission,
    material_generation: u64,
    material: Zeroizing<Vec<u8>>,
    accessed: Rc<Cell<usize>>,
}

impl Lease {
    fn new(operation: AnthropicOperation) -> Self {
        let credential_id = CredentialId::parse("11111111-1111-4111-8111-111111111111").unwrap();
        let permission = GrantPermission {
            operation: BrokerOperationId::parse(operation.operation_name()).unwrap(),
            route: BrokerRouteId::parse(ROUTE).unwrap(),
        };
        Self {
            metadata: CredentialMetadata {
                id: credential_id.clone(),
                placement: Placement::Platform,
                owner: Owner::User(OwnerId::parse("synthetic-owner").unwrap()),
                provider: ProviderId::parse("anthropic").unwrap(),
                authentication_kind: CredentialAuthKind::OAuth,
                display_name: "synthetic-claude-subscription".into(),
                account_hint: None,
                ssh_public_key: None,
                status: CredentialStatus::Active,
                expires_at_unix: Some(4_102_444_800),
                revocation_generation: 7,
            },
            grant: DerivedGrant {
                environment_id: EnvironmentId::parse("synthetic-environment").unwrap(),
                environment_generation: 3,
                profile: Some(GrantProfile {
                    id: AccessProfileId::parse("22222222-2222-4222-8222-222222222222").unwrap(),
                    revision: 4,
                }),
                capability_slot: CapabilitySlot::anthropic(),
                credential_id,
                credential_revocation_generation: 7,
                expires_at_unix: Some(4_102_444_800),
                permissions: BTreeSet::from([permission.clone()]),
            },
            permission,
            material_generation: 2,
            material: Zeroizing::new(TOKEN.to_vec()),
            accessed: Rc::new(Cell::new(0)),
        }
    }
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
        self.material_generation
    }
    fn with_material<T>(self, operation: impl FnOnce(&[u8]) -> T) -> T {
        self.accessed.set(self.accessed.get() + 1);
        operation(&self.material)
    }
}

/// The request headers Claude Code 2.1.238 sends in subscription mode.
fn claude_code_headers() -> HeaderMap {
    let mut headers = HeaderMap::new();
    let betas = claude_code_betas();
    for (name, value) in [
        ("accept", "application/json"),
        ("accept-encoding", "gzip, deflate, br, zstd"),
        ("anthropic-beta", betas.as_str()),
        ("anthropic-dangerous-direct-browser-access", "true"),
        ("anthropic-version", "2023-06-01"),
        ("authorization", "Bearer codewire-managed"),
        ("connection", "keep-alive"),
        ("content-type", "application/json"),
        ("host", "127.0.0.1:38081"),
        ("user-agent", USER_AGENT),
        ("x-app", "cli"),
        ("x-claude-code-session-id", SESSION),
        ("x-stainless-arch", "x64"),
        ("x-stainless-lang", "js"),
        ("x-stainless-os", "Linux"),
        ("x-stainless-package-version", "0.112.1"),
        ("x-stainless-retry-count", "0"),
        ("x-stainless-runtime", "node"),
        ("x-stainless-runtime-version", "v26.3.0"),
        ("x-stainless-timeout", "600"),
    ] {
        headers.insert(
            HeaderName::from_static(name),
            HeaderValue::from_str(value).unwrap(),
        );
    }
    headers
}

fn prepare(
    lease: Lease,
    path: &str,
    query: Option<&str>,
    headers: HeaderMap,
) -> Result<PreparedAnthropicRequest, CredentialBrokerError> {
    let request = AnthropicApiKeyAdapter::new().unwrap().validate_request(
        &Method::POST,
        path,
        query,
        headers,
        BODY.to_vec(),
    )?;
    AnthropicSubscriptionTokenAdapter::new()
        .unwrap()
        .prepare_validated(lease, request)
}

fn denied_before_material(headers: HeaderMap) {
    let lease = Lease::new(AnthropicOperation::Messages);
    let accessed = lease.accessed.clone();
    assert_eq!(
        prepare(lease, "/messages", Some("beta=true"), headers).err(),
        Some(CredentialBrokerError::RequestDenied)
    );
    assert_eq!(accessed.get(), 0);
}

#[test]
fn the_stored_token_replaces_the_placeholder_bearer_on_both_exact_routes() {
    for (path, operation) in [
        ("/messages", AnthropicOperation::Messages),
        ("/messages/count_tokens", AnthropicOperation::CountTokens),
    ] {
        for query in [None, Some("beta=true")] {
            let lease = Lease::new(operation);
            let accessed = lease.accessed.clone();
            let (method, target, outbound, body, _) =
                prepare(lease, path, query, claude_code_headers())
                    .unwrap()
                    .into_parts();
            assert_eq!(method, Method::POST);
            assert_eq!(target.scheme(), "https");
            assert_eq!(target.host_str(), Some("api.anthropic.com"));
            assert_eq!(target.port_or_known_default(), Some(443));
            assert_eq!(target.path(), format!("/v1{path}"));
            assert_eq!(target.query(), query);
            assert_eq!(body, BODY);
            let authorization = &outbound[header::AUTHORIZATION];
            assert_eq!(
                authorization.as_bytes(),
                [b"Bearer ".as_slice(), TOKEN].concat()
            );
            assert!(authorization.is_sensitive());
            assert!(!outbound.contains_key("x-api-key"));
            assert_eq!(accessed.get(), 1);
            // Exactly the API-key adapter's request headers plus Claude
            // Code's four identity headers; no SDK telemetry or framing.
            assert_eq!(
                outbound
                    .keys()
                    .map(HeaderName::as_str)
                    .collect::<BTreeSet<_>>(),
                BTreeSet::from([
                    "accept",
                    "accept-encoding",
                    "anthropic-beta",
                    "anthropic-dangerous-direct-browser-access",
                    "anthropic-version",
                    "authorization",
                    "content-type",
                    "user-agent",
                    "x-app",
                    "x-claude-code-session-id",
                ])
            );
            assert_eq!(outbound.len(), 10);
            assert_eq!(outbound[header::ACCEPT_ENCODING], "identity");
            assert_eq!(outbound[header::USER_AGENT], USER_AGENT);
            assert_eq!(outbound["x-app"], "cli");
            assert_eq!(
                outbound["anthropic-dangerous-direct-browser-access"],
                "true"
            );
            assert_eq!(outbound["x-claude-code-session-id"], SESSION);
            assert_eq!(outbound["anthropic-beta"], claude_code_betas());
        }
    }
}

#[test]
fn the_oauth_beta_is_added_once_when_the_caller_omits_it() {
    for (input, expected) in [
        (None, "oauth-2025-04-20"),
        (
            Some("claude-code-20250219"),
            "claude-code-20250219,oauth-2025-04-20",
        ),
        (
            Some("claude-code-20250219, context-1m-2025-08-07"),
            "claude-code-20250219, context-1m-2025-08-07,oauth-2025-04-20",
        ),
        (
            Some("oauth-2025-04-20, claude-code-20250219"),
            "oauth-2025-04-20, claude-code-20250219",
        ),
    ] {
        let mut headers = claude_code_headers();
        headers.remove("anthropic-beta");
        if let Some(input) = input {
            headers.insert("anthropic-beta", HeaderValue::from_static(input));
        }
        let (_, _, outbound, _, _) = prepare(
            Lease::new(AnthropicOperation::Messages),
            "/messages",
            None,
            headers,
        )
        .unwrap()
        .into_parts();
        assert_eq!(outbound["anthropic-beta"], expected);
        assert_eq!(outbound.get_all("anthropic-beta").iter().count(), 1);
    }
}

#[test]
fn only_an_absent_or_exact_placeholder_bearer_is_accepted_and_never_forwarded() {
    let mut absent = claude_code_headers();
    absent.remove(header::AUTHORIZATION);
    // A caller's API key header is dropped, never forwarded or substituted.
    absent.insert("x-api-key", HeaderValue::from_static("guest-controlled"));
    let (_, _, outbound, _, _) = prepare(
        Lease::new(AnthropicOperation::Messages),
        "/messages",
        None,
        absent,
    )
    .unwrap()
    .into_parts();
    assert_eq!(
        outbound[header::AUTHORIZATION].as_bytes(),
        [b"Bearer ".as_slice(), TOKEN].concat()
    );
    assert!(!outbound.contains_key("x-api-key"));
    assert!(!outbound.values().any(|value| value == "guest-controlled"));

    for value in [
        "Bearer sk-ant-oat01-guest-supplied",
        "Bearer codewire-managed ",
        "bearer codewire-managed",
        "Bearer",
        "",
        "Basic Y29kZXdpcmUtbWFuYWdlZA==",
    ] {
        let mut headers = claude_code_headers();
        headers.insert(header::AUTHORIZATION, HeaderValue::from_static(value));
        denied_before_material(headers);
    }
    let mut duplicate = claude_code_headers();
    duplicate.append(
        header::AUTHORIZATION,
        HeaderValue::from_static("Bearer codewire-managed"),
    );
    denied_before_material(duplicate);
}

#[test]
fn claude_code_identity_headers_are_exact_bounded_single_values() {
    let long_user_agent = format!("claude-cli/{}", "9".repeat(MAX_USER_AGENT_BYTES));
    let long_session = "a".repeat(MAX_SESSION_ID_BYTES + 1);
    let long_app = "a".repeat(MAX_APP_BYTES + 1);
    for (name, value) in [
        ("user-agent", long_user_agent.as_str()),
        ("user-agent", "claude-cli/2.1.238\t(external)"),
        ("x-app", ""),
        ("x-app", "cli tool"),
        ("x-app", long_app.as_str()),
        ("anthropic-dangerous-direct-browser-access", "false"),
        ("anthropic-dangerous-direct-browser-access", "TRUE"),
        ("x-claude-code-session-id", "not a uuid"),
        ("x-claude-code-session-id", "id/../other"),
        ("x-claude-code-session-id", long_session.as_str()),
    ] {
        let mut headers = claude_code_headers();
        headers.insert(
            HeaderName::from_static(name),
            HeaderValue::from_str(value).unwrap(),
        );
        denied_before_material(headers);
    }
    let mut non_ascii = claude_code_headers();
    non_ascii.insert(
        header::USER_AGENT,
        HeaderValue::from_bytes(b"claude-cli/\x80").unwrap(),
    );
    denied_before_material(non_ascii);
    for name in [
        "user-agent",
        "x-app",
        "anthropic-dangerous-direct-browser-access",
        "x-claude-code-session-id",
    ] {
        let mut duplicate = claude_code_headers();
        let value = duplicate[name].clone();
        duplicate.append(HeaderName::from_static(name), value);
        denied_before_material(duplicate);
    }
    // Each identity header is optional; absent ones are simply not sent.
    let mut minimal = claude_code_headers();
    for name in [
        "user-agent",
        "x-app",
        "anthropic-dangerous-direct-browser-access",
        "x-claude-code-session-id",
    ] {
        minimal.remove(name);
    }
    let (_, _, outbound, _, _) = prepare(
        Lease::new(AnthropicOperation::Messages),
        "/messages",
        None,
        minimal,
    )
    .unwrap()
    .into_parts();
    assert_eq!(outbound.len(), 6);
}

#[test]
fn every_lease_coordinate_and_the_oauth_kind_are_checked_before_the_token() {
    for case in 0..16 {
        let mut lease = Lease::new(AnthropicOperation::Messages);
        match case {
            0 => lease.metadata.provider = ProviderId::parse("openai").unwrap(),
            1 => lease.metadata.authentication_kind = CredentialAuthKind::ApiKey,
            2 => lease.metadata.status = CredentialStatus::Revoked,
            3 => lease.metadata.status = CredentialStatus::RefreshFailed,
            4 => lease.grant.credential_revocation_generation += 1,
            5 => lease.metadata.expires_at_unix = Some(0),
            6 => lease.grant.expires_at_unix = Some(0),
            7 => lease.grant.capability_slot = CapabilitySlot::codex(),
            8 => {
                lease.grant.credential_id =
                    CredentialId::parse("33333333-3333-4333-8333-333333333333").unwrap()
            }
            9 => lease.grant.environment_generation = 0,
            10 => lease.grant.profile.as_mut().unwrap().revision = 0,
            11 => lease.material_generation = 0,
            12 => lease.permission.operation = BrokerOperationId::parse("count-tokens").unwrap(),
            13 => lease.permission.route = BrokerRouteId::parse("openai-api").unwrap(),
            14 => lease.metadata.status = CredentialStatus::Expired,
            _ => lease.grant.permissions.clear(),
        }
        let accessed = lease.accessed.clone();
        assert_eq!(
            prepare(lease, "/messages", None, claude_code_headers()).err(),
            Some(CredentialBrokerError::UnsupportedLease),
            "case {case}"
        );
        assert_eq!(accessed.get(), 0, "case {case}");
    }
    // The API-key adapter still refuses the subscription form.
    let lease = Lease::new(AnthropicOperation::Messages);
    let accessed = lease.accessed.clone();
    let request = AnthropicApiKeyAdapter::new()
        .unwrap()
        .validate_request(
            &Method::POST,
            "/messages",
            None,
            claude_code_headers(),
            BODY.to_vec(),
        )
        .unwrap();
    assert_eq!(
        AnthropicApiKeyAdapter::new()
            .unwrap()
            .prepare_validated(lease, request)
            .err(),
        Some(CredentialBrokerError::UnsupportedLease)
    );
    assert_eq!(accessed.get(), 0);
}

#[test]
fn malformed_empty_and_oversized_tokens_are_closed_value_blind_errors() {
    for material in [
        vec![],
        b"token\ncanary".to_vec(),
        b"token canary".to_vec(),
        b"token\0canary".to_vec(),
        vec![0xff],
        vec![b'x'; MAX_KEY_BYTES + 1],
    ] {
        let mut lease = Lease::new(AnthropicOperation::Messages);
        lease.material = Zeroizing::new(material);
        let error = prepare(lease, "/messages", None, claude_code_headers())
            .err()
            .unwrap();
        assert_eq!(error, CredentialBrokerError::InvalidCredentialMaterial);
        assert!(!format!("{error:?}: {error}").contains("canary"));
    }
}

#[test]
fn token_reflections_are_redacted_and_only_this_form_returns_plan_rate_limits() {
    let prepared = |adapter_is_subscription: bool| {
        let headers = claude_code_headers();
        if adapter_is_subscription {
            prepare(
                Lease::new(AnthropicOperation::Messages),
                "/messages",
                None,
                headers,
            )
            .unwrap()
            .into_parts()
            .4
        } else {
            let mut lease = Lease::new(AnthropicOperation::Messages);
            lease.metadata.authentication_kind = CredentialAuthKind::ApiKey;
            AnthropicApiKeyAdapter::new()
                .unwrap()
                .prepare(lease, &Method::POST, "/messages", None, &headers, BODY)
                .unwrap()
                .into_parts()
                .4
        }
    };
    let mut upstream = HeaderMap::new();
    upstream.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/event-stream"),
    );
    upstream.insert("request-id", HeaderValue::from_bytes(TOKEN).unwrap());
    for name in SUBSCRIPTION_RATE_LIMIT_HEADERS {
        upstream.insert(
            HeaderName::from_static(name),
            HeaderValue::from_static("0.42"),
        );
    }
    upstream.insert("x-unknown", HeaderValue::from_static("must-not-return"));
    let (subscription, mut body) = prepared(true).begin(&upstream).unwrap();
    assert_eq!(subscription["request-id"], "[REDACTED]");
    for name in SUBSCRIPTION_RATE_LIMIT_HEADERS {
        assert_eq!(subscription[*name], "0.42", "{name}");
    }
    assert_eq!(
        subscription.len(),
        2 + SUBSCRIPTION_RATE_LIMIT_HEADERS.len()
    );
    assert!(!subscription.contains_key("x-unknown"));
    let mut output = body.push(b"data: ").unwrap();
    let encoded = STANDARD.encode(TOKEN);
    output.extend(body.push(&encoded.as_bytes()[..5]).unwrap());
    output.extend(body.push(&encoded.as_bytes()[5..]).unwrap());
    output.extend(body.push(b" ").unwrap());
    output.extend(body.push(TOKEN).unwrap());
    output.extend(body.finish().unwrap());
    assert_eq!(output, b"data: [REDACTED] [REDACTED]");

    // The API-key form's response allowlist is unchanged.
    let (api_key, _) = prepared(false).begin(&upstream).unwrap();
    assert_eq!(api_key.len(), 2);
    for name in SUBSCRIPTION_RATE_LIMIT_HEADERS {
        assert!(!api_key.contains_key(*name), "{name}");
    }
    assert_eq!(
        response_headers().len(),
        RESPONSE_HEADERS.len() + SUBSCRIPTION_RATE_LIMIT_HEADERS.len()
    );
}

#[test]
fn shared_pre_lease_validation_still_denies_before_any_lease() {
    let adapter = AnthropicApiKeyAdapter::new().unwrap();
    for (method, path, query) in [
        (Method::GET, "/messages", None),
        (Method::POST, "/models", None),
        (Method::POST, "/messages", Some("beta=false")),
        (Method::POST, "/oauth/token", None),
    ] {
        assert_eq!(
            adapter
                .validate_request(&method, path, query, claude_code_headers(), BODY.to_vec())
                .err(),
            Some(CredentialBrokerError::RequestDenied)
        );
    }
    let mut workspace = claude_code_headers();
    workspace.insert("anthropic-workspace-id", HeaderValue::from_static("ws"));
    assert!(
        adapter
            .validate_request(&Method::POST, "/messages", None, workspace, BODY.to_vec())
            .is_err()
    );
}
