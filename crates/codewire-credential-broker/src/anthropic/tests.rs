use std::cell::Cell;
use std::collections::BTreeSet;
use std::rc::Rc;

use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD},
};
use codewire_access::{
    AccessProfileId, BrokerOperationId, BrokerRouteId, CapabilitySlot, CredentialId,
    CredentialMetadata, DerivedGrant, EnvironmentId, GrantPermission, GrantProfile, Owner, OwnerId,
    Placement, ProviderId,
};
use http::{HeaderName, HeaderValue, header};
use zeroize::Zeroizing;

use super::*;

const KEY: &[u8] = b"CW_TEST_ANTHROPIC_key+/=_~\"\\";
/// Claude Code's server-side auto mode request field rides in the body.
const BODY: &[u8] = br#"{"model":"synthetic-model","max_tokens":64,"messages":[{"role":"user","content":"hello"}],"stream":true,"safeguards":[{"type":"dangerous_tool_use","classifier_context":{"v":1,"permission_mode":"auto"}}],"unknown_future_field":{"a":[1,2]}}"#;

pub(super) struct Lease {
    pub(super) metadata: CredentialMetadata,
    pub(super) grant: DerivedGrant,
    pub(super) permission: GrantPermission,
    pub(super) material_generation: u64,
    pub(super) material: Zeroizing<Vec<u8>>,
    pub(super) accessed: Rc<Cell<usize>>,
}

impl Lease {
    pub(super) fn new(kind: CredentialAuthKind, material: &[u8]) -> Self {
        let credential_id = CredentialId::parse("11111111-1111-4111-8111-111111111111").unwrap();
        let permission = GrantPermission {
            operation: BrokerOperationId::parse(OPERATION).unwrap(),
            route: BrokerRouteId::parse(ROUTE).unwrap(),
        };
        Self {
            metadata: CredentialMetadata {
                id: credential_id.clone(),
                placement: Placement::Local,
                owner: Owner::User(OwnerId::parse("synthetic-owner").unwrap()),
                provider: ProviderId::parse(PROVIDER).unwrap(),
                authentication_kind: kind,
                display_name: "synthetic-anthropic".into(),
                account_hint: None,
                ssh_public_key: None,
                status: CredentialStatus::Active,
                expires_at_unix: None,
                revocation_generation: 7,
            },
            grant: DerivedGrant {
                environment_id: EnvironmentId::parse("synthetic-environment").unwrap(),
                environment_generation: 3,
                profile: Some(GrantProfile {
                    id: AccessProfileId::parse("22222222-2222-4222-8222-222222222222").unwrap(),
                    revision: 4,
                }),
                capability_slot: CapabilitySlot::parse(PROVIDER).unwrap(),
                credential_id,
                credential_revocation_generation: 7,
                expires_at_unix: None,
                permissions: BTreeSet::from([permission.clone()]),
            },
            permission,
            material_generation: 2,
            material: Zeroizing::new(material.to_vec()),
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

fn api_key_lease() -> Lease {
    Lease::new(CredentialAuthKind::ApiKey, KEY)
}

/// What Claude Code 2.1.288 sends, plus guest credentials and framing that
/// must never pass.
pub(super) fn claude_headers() -> HeaderMap {
    let mut headers = HeaderMap::new();
    for (name, value) in [
        ("content-type", "application/json"),
        ("accept", "application/json"),
        ("anthropic-version", "2023-06-01"),
        (
            "anthropic-beta",
            "claude-code-20250219,dangerous-tool-use-2026-09-03",
        ),
        ("user-agent", "claude-cli/2.1.288 (external, cli)"),
        ("x-app", "cli"),
        (
            "x-claude-code-session-id",
            "6f2a1f0e-0000-4000-8000-000000000001",
        ),
        ("x-stainless-lang", "js"),
        ("anthropic-workspace-id", "wrkspc_synthetic"),
        ("authorization", "Bearer codewire-managed"),
        ("x-api-key", "guest-supplied-key"),
        ("cookie", "guest=cookie"),
        ("proxy-authorization", "Basic guest"),
        ("host", "127.0.0.1:38081"),
        ("accept-encoding", "gzip, br"),
    ] {
        headers.append(
            HeaderName::from_static(name),
            HeaderValue::from_static(value),
        );
    }
    headers
}

fn prepare(
    lease: Lease,
    method: &Method,
    path: &str,
    query: Option<&str>,
    headers: &HeaderMap,
    body: &[u8],
) -> Result<PreparedAnthropicRequest, CredentialBrokerError> {
    AnthropicApiKeyAdapter::new()
        .unwrap()
        .prepare(lease, method, path, query, headers, body)
}

fn prepared_response() -> PreparedAnthropicResponse {
    prepare(
        api_key_lease(),
        &Method::POST,
        "/v1/messages",
        None,
        &claude_headers(),
        BODY,
    )
    .unwrap()
    .into_parts()
    .4
}

fn response_headers(content_type: &'static str) -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(header::CONTENT_TYPE, HeaderValue::from_static(content_type));
    headers
}

#[test]
fn any_path_method_query_header_and_body_reach_the_provider_unchanged() {
    let guest = claude_headers();
    for (method, path, query, body) in [
        (Method::POST, "/v1/messages", Some("beta=true"), BODY),
        (Method::POST, "/v1/messages/count_tokens", None, BODY),
        (Method::GET, "/api/oauth/usage", None, b"".as_slice()),
        (
            Method::GET,
            "/v1/models",
            Some("limit=20&after_id=x"),
            b"".as_slice(),
        ),
        (Method::DELETE, "/v1/files/file_abc", None, b"".as_slice()),
        (Method::POST, "/v1/messages/batches", None, BODY),
    ] {
        let (sent_method, target, headers, sent_body, _) =
            prepare(api_key_lease(), &method, path, query, &guest, body)
                .unwrap()
                .into_parts();
        assert_eq!(sent_method, method);
        let expected = match query {
            Some(query) => format!("https://api.anthropic.com{path}?{query}"),
            None => format!("https://api.anthropic.com{path}"),
        };
        assert_eq!(target.as_str(), expected);
        assert_eq!(sent_body, body, "body is byte-exact");
        for kept in [
            "content-type",
            "accept",
            "anthropic-version",
            "anthropic-beta",
            "user-agent",
            "x-app",
            "x-claude-code-session-id",
            "x-stainless-lang",
            "anthropic-workspace-id",
        ] {
            assert_eq!(headers.get(kept), guest.get(kept), "{kept}");
        }
        for gone in ["authorization", "cookie", "proxy-authorization", "host"] {
            assert!(!headers.contains_key(gone), "{gone}");
        }
        assert_eq!(
            headers["x-api-key"].as_bytes(),
            KEY,
            "only the injected key"
        );
        assert_eq!(headers.get_all("x-api-key").iter().count(), 1);
        assert_eq!(headers["accept-encoding"], "identity");
    }
}

#[test]
fn unsafe_shapes_and_upgrades_fail_before_material() {
    let mut upgrade = claude_headers();
    upgrade.insert("upgrade", HeaderValue::from_static("websocket"));
    for (method, path, headers, body) in [
        (
            Method::OPTIONS,
            "/v1/messages",
            claude_headers(),
            BODY.to_vec(),
        ),
        (Method::POST, "/v1/../x", claude_headers(), BODY.to_vec()),
        (Method::POST, "v1/messages", claude_headers(), BODY.to_vec()),
        (
            Method::POST,
            "/v1//messages",
            claude_headers(),
            BODY.to_vec(),
        ),
        (Method::GET, "/v1/messages", upgrade, Vec::new()),
        (
            Method::POST,
            "/v1/messages",
            claude_headers(),
            vec![b'x'; MAX_REQUEST_BYTES + 1],
        ),
    ] {
        let lease = api_key_lease();
        let accessed = lease.accessed.clone();
        assert_eq!(
            prepare(lease, &method, path, None, &headers, &body).err(),
            Some(CredentialBrokerError::RequestDenied),
            "{method} {path}"
        );
        assert_eq!(accessed.get(), 0);
    }
}

#[test]
fn every_lease_coordinate_and_expiry_is_checked_before_borrowing_material() {
    for case in 0..15 {
        let mut lease = api_key_lease();
        match case {
            0 => lease.metadata.provider = ProviderId::parse("openai").unwrap(),
            1 => lease.metadata.authentication_kind = CredentialAuthKind::OAuth,
            2 => lease.metadata.status = CredentialStatus::Revoked,
            3 => lease.metadata.revocation_generation = 0,
            4 => lease.grant.credential_revocation_generation += 1,
            5 => lease.metadata.expires_at_unix = Some(0),
            6 => lease.grant.expires_at_unix = Some(0),
            7 => lease.grant.capability_slot = CapabilitySlot::parse("codex").unwrap(),
            8 => {
                lease.grant.credential_id =
                    CredentialId::parse("33333333-3333-4333-8333-333333333333").unwrap()
            }
            9 => lease.grant.environment_generation = 0,
            10 => lease.grant.profile.as_mut().unwrap().revision = 0,
            11 => lease.material_generation = 0,
            12 => lease.permission.operation = BrokerOperationId::parse("count-tokens").unwrap(),
            13 => lease.permission.route = BrokerRouteId::parse("openai-api").unwrap(),
            _ => lease.grant.permissions.clear(),
        }
        let accessed = lease.accessed.clone();
        assert_eq!(
            prepare(
                lease,
                &Method::POST,
                "/v1/messages",
                None,
                &claude_headers(),
                BODY
            )
            .err(),
            Some(CredentialBrokerError::UnsupportedLease),
            "case {case}"
        );
        assert_eq!(accessed.get(), 0, "case {case}");
    }
}

#[test]
fn malformed_empty_and_oversized_api_keys_are_closed_value_blind_errors() {
    for material in [
        vec![],
        b"key\ncanary".to_vec(),
        b"key\rcanary".to_vec(),
        b"key\0canary".to_vec(),
        b"key canary".to_vec(),
        vec![0xff],
        vec![b'x'; MAX_KEY_BYTES + 1],
    ] {
        let lease = Lease::new(CredentialAuthKind::ApiKey, &material);
        let error = prepare(
            lease,
            &Method::POST,
            "/v1/messages",
            None,
            &claude_headers(),
            BODY,
        )
        .err()
        .unwrap();
        assert_eq!(error, CredentialBrokerError::InvalidCredentialMaterial);
        assert!(!format!("{error:?}: {error}").contains("canary"));
    }
}

#[test]
fn every_response_header_passes_except_framing_and_cookies() {
    let mut upstream = response_headers("text/event-stream");
    for (name, value) in [
        ("request-id", "req_synthetic"),
        ("anthropic-ratelimit-unified-5h-utilization", "0.25"),
        ("anthropic-organization-id", "org_synthetic"),
        ("x-future-provider-header", "kept"),
        ("set-cookie", "provider=cookie"),
        ("content-length", "12"),
        ("connection", "close"),
    ] {
        upstream.insert(
            HeaderName::from_static(name),
            HeaderValue::from_static(value),
        );
    }
    let (headers, _) = prepared_response().begin(&upstream).unwrap();
    for kept in [
        "content-type",
        "request-id",
        "anthropic-ratelimit-unified-5h-utilization",
        "anthropic-organization-id",
        "x-future-provider-header",
    ] {
        assert_eq!(headers.get(kept), upstream.get(kept), "{kept}");
    }
    for gone in ["set-cookie", "content-length", "connection"] {
        assert!(!headers.contains_key(gone), "{gone}");
    }
    let mut encoded = response_headers("application/json");
    encoded.insert("content-encoding", HeaderValue::from_static("gzip"));
    assert_eq!(
        prepared_response().begin(&encoded).err(),
        Some(CredentialBrokerError::ResponseDenied)
    );
}

#[test]
fn safeguard_results_survive_json_and_sse_unchanged() {
    let json = br#"{"id":"msg_1","content":[{"type":"tool_use","id":"toolu_01ABC","name":"Bash","input":{}}],"safeguard_results":[{"type":"dangerous_tool_use","status":{"type":"available","tool_uses":{"toolu_01ABC":{"type":"evaluated","outcome":"not_flagged"}}}}]}"#;
    let sse = b"event: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"tool_use\",\"id\":\"toolu_01ABC\",\"name\":\"Bash\",\"input\":{}}}\n\nevent: message_delta\ndata: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"tool_use\"},\"safeguard_results\":[{\"type\":\"dangerous_tool_use\",\"status\":{\"type\":\"available\",\"tool_uses\":{\"toolu_01ABC\":{\"type\":\"evaluated\",\"outcome\":\"not_flagged\"}}}}]}\n\nevent: message_stop\ndata: {\"type\":\"message_stop\"}\n\n";
    for (content_type, body) in [
        ("application/json", json.as_slice()),
        ("text/event-stream", sse.as_slice()),
    ] {
        let (_, mut response) = prepared_response()
            .begin(&response_headers(content_type))
            .unwrap();
        let mut output = Vec::new();
        for byte in body {
            output.extend(response.push(&[*byte]).unwrap());
        }
        output.extend(response.finish().unwrap());
        assert_eq!(output, body);
    }
}

pub(super) fn reflections(key: &[u8]) -> Vec<Vec<u8>> {
    let raw = std::str::from_utf8(key).unwrap();
    let json = serde_json::to_string(raw).unwrap();
    let percent = url::form_urlencoded::byte_serialize(key).collect::<String>();
    let mut lower_percent = percent.as_bytes().to_vec();
    let mut index = 0;
    while index < lower_percent.len() {
        if lower_percent[index] == b'%' {
            lower_percent[index + 1].make_ascii_lowercase();
            lower_percent[index + 2].make_ascii_lowercase();
            index += 3;
        } else {
            index += 1;
        }
    }
    vec![
        key.to_vec(),
        STANDARD.encode(key).into_bytes(),
        STANDARD_NO_PAD.encode(key).into_bytes(),
        URL_SAFE.encode(key).into_bytes(),
        URL_SAFE_NO_PAD.encode(key).into_bytes(),
        percent.as_bytes().to_vec(),
        lower_percent,
        json.as_bytes()[1..json.len() - 1].to_vec(),
    ]
}

#[test]
fn raw_json_percent_and_base64_reflections_are_redacted_in_bodies_and_any_header() {
    for reflection in reflections(KEY) {
        for split in 0..=reflection.len() {
            let (_, mut response) = prepared_response()
                .begin(&response_headers("text/event-stream"))
                .unwrap();
            let mut output = response.push(b"event: error\ndata: ").unwrap();
            output.extend(response.push(&reflection[..split]).unwrap());
            output.extend(response.push(&reflection[split..]).unwrap());
            output.extend(response.push(b"\n\n").unwrap());
            output.extend(response.finish().unwrap());
            assert_eq!(
                output, b"event: error\ndata: [REDACTED]\n\n",
                "split {split}"
            );
        }
        let mut headers = response_headers("application/json");
        headers.insert(
            "x-any-provider-header",
            HeaderValue::from_bytes(&reflection).unwrap(),
        );
        let (headers, _) = prepared_response().begin(&headers).unwrap();
        assert_eq!(headers["x-any-provider-header"], "[REDACTED]");
    }
}

#[test]
fn response_body_ceiling_is_terminal_and_never_flushes_pending_material_after_failure() {
    let mut prepared = prepared_response();
    prepared.max_body_bytes = KEY.len();
    let (_, mut response) = prepared
        .begin(&response_headers("application/json"))
        .unwrap();
    assert!(response.push(&KEY[..KEY.len() - 1]).unwrap().is_empty());
    assert_eq!(
        response.push(b"too-long").unwrap_err(),
        CredentialBrokerError::ResponseTooLarge
    );
    assert_eq!(
        response.push(b"").unwrap_err(),
        CredentialBrokerError::ResponseTooLarge
    );
    assert_eq!(
        response.finish().unwrap_err(),
        CredentialBrokerError::ResponseTooLarge
    );
}
