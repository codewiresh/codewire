use std::cell::Cell;
use std::rc::Rc;

use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD},
};
use codewire_access::{
    AccessProfileId, BrokerOperationId, BrokerRouteId, CapabilitySlot, CredentialId,
    CredentialMetadata, DerivedGrant, EnvironmentId, GrantPermission, Owner, OwnerId, Placement,
    ProviderId,
};
use zeroize::Zeroizing;

use super::*;

const KEY: &[u8] = b"CW_TEST_ANTHROPIC_key+/=_~\"\\";
const BODY: &[u8] = br#"{"model":"synthetic-model","max_tokens":64,"messages":[{"role":"user","content":"hello"}],"stream":true}"#;

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
                placement: Placement::Local,
                owner: Owner::User(OwnerId::parse("synthetic-owner").unwrap()),
                provider: ProviderId::parse(PROVIDER).unwrap(),
                authentication_kind: CredentialAuthKind::ApiKey,
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
                profile_id: AccessProfileId::parse("22222222-2222-4222-8222-222222222222").unwrap(),
                profile_revision: 4,
                capability_slot: CapabilitySlot::parse(PROVIDER).unwrap(),
                credential_id,
                credential_revocation_generation: 7,
                expires_at_unix: None,
                permissions: BTreeSet::from([permission.clone()]),
            },
            permission,
            material_generation: 2,
            material: Zeroizing::new(KEY.to_vec()),
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

fn headers() -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    headers.insert("anthropic-version", HeaderValue::from_static(API_VERSION));
    headers.insert(header::ACCEPT, HeaderValue::from_static("application/json"));
    headers
}

fn response_headers(content_type: &'static str) -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(header::CONTENT_TYPE, HeaderValue::from_static(content_type));
    headers
}

fn prepared_response(operation: AnthropicOperation) -> PreparedAnthropicResponse {
    let path = match operation {
        AnthropicOperation::Messages => "/messages",
        AnthropicOperation::CountTokens => "/messages/count_tokens",
    };
    AnthropicApiKeyAdapter::new()
        .unwrap()
        .prepare(
            Lease::new(operation),
            &Method::POST,
            path,
            None,
            &headers(),
            BODY,
        )
        .unwrap()
        .into_parts()
        .4
}

#[test]
fn exact_messages_and_count_routes_preserve_sdk_beta_query_and_plain_bodies() {
    let adapter = AnthropicApiKeyAdapter::new().unwrap();
    for (path, operation) in [
        ("/messages", AnthropicOperation::Messages),
        ("/messages/count_tokens", AnthropicOperation::CountTokens),
    ] {
        for query in [None, Some(""), Some("beta=true")] {
            let mut headers = headers();
            headers.insert(
                "anthropic-beta",
                HeaderValue::from_static("token-counting-2024-11-01,context-management-2025-06-27"),
            );
            let request = adapter
                .validate_request(&Method::POST, path, query, headers, BODY.to_vec())
                .unwrap();
            assert_eq!(request.operation(), operation);
            let lease = Lease::new(operation);
            let accessed = lease.accessed.clone();
            let (method, target, outbound, body, _) = adapter
                .prepare_validated(lease, request)
                .unwrap()
                .into_parts();
            assert_eq!(method, Method::POST);
            assert_eq!(target.scheme(), "https");
            assert_eq!(target.host_str(), Some("api.anthropic.com"));
            assert_eq!(target.port_or_known_default(), Some(443));
            assert_eq!(target.path(), format!("/v1{path}"));
            assert_eq!(target.query(), query.filter(|query| !query.is_empty()));
            assert_eq!(body, BODY);
            assert_eq!(outbound["anthropic-version"], API_VERSION);
            assert_eq!(outbound[header::ACCEPT_ENCODING], "identity");
            assert_eq!(outbound["x-api-key"].as_bytes(), KEY);
            assert!(outbound["x-api-key"].is_sensitive());
            assert!(outbound.contains_key("anthropic-beta"));
            assert_eq!(accessed.get(), 1);
        }
    }
}

#[test]
fn caller_credentials_authority_framing_and_sdk_telemetry_are_not_forwarded() {
    let mut input = headers();
    for name in [
        "authorization",
        "x-api-key",
        "cookie",
        "proxy-authorization",
        "host",
        "connection",
        "transfer-encoding",
        "content-length",
        "user-agent",
        "x-stainless-retry-count",
        "x-forwarded-host",
        "x-error-json",
        "accept-encoding",
    ] {
        input.insert(
            HeaderName::from_static(name),
            HeaderValue::from_static("guest-controlled"),
        );
    }
    let (_, _, outbound, _, _) = AnthropicApiKeyAdapter::new()
        .unwrap()
        .prepare(
            Lease::new(AnthropicOperation::Messages),
            &Method::POST,
            "/messages",
            None,
            &input,
            BODY,
        )
        .unwrap()
        .into_parts();
    assert_eq!(outbound.len(), 5);
    assert_eq!(outbound["x-api-key"].as_bytes(), KEY);
    assert_eq!(outbound[header::ACCEPT_ENCODING], "identity");
    assert!(!outbound.values().any(|value| value == "guest-controlled"));
}

fn denied_before_material(
    method: &Method,
    path: &str,
    query: Option<&str>,
    headers: &HeaderMap,
    body: &[u8],
) {
    let lease = Lease::new(AnthropicOperation::Messages);
    let accessed = lease.accessed.clone();
    let result = AnthropicApiKeyAdapter::new()
        .unwrap()
        .prepare(lease, method, path, query, headers, body);
    assert_eq!(result.err(), Some(CredentialBrokerError::RequestDenied));
    assert_eq!(accessed.get(), 0);
}

#[test]
fn unsupported_methods_paths_aliases_and_queries_fail_before_material() {
    for method in [
        Method::GET,
        Method::PUT,
        Method::DELETE,
        Method::PATCH,
        Method::CONNECT,
        Method::OPTIONS,
        Method::HEAD,
    ] {
        denied_before_material(&method, "/messages", None, &headers(), BODY);
    }
    for path in [
        "messages",
        "//messages",
        "/messages/",
        "/messages//count_tokens",
        "/v1/messages",
        "/messages/../messages",
        "/messages/%2e%2e/messages",
        "/messages%2fcount_tokens",
        "/messages?beta=true",
        "/models",
        "/files",
        "/messages/batches",
        "/complete",
        "/oauth/token",
        "https://evil.test/messages",
    ] {
        denied_before_material(&Method::POST, path, None, &headers(), BODY);
    }
    for query in [
        "beta=false",
        "beta=true&beta=true",
        "beta=true&",
        "beta=true&host=evil.test",
        "b%65ta=true",
        "beta=%74rue",
        "api_key=value",
        "?beta=true",
    ] {
        denied_before_material(&Method::POST, "/messages", Some(query), &headers(), BODY);
    }
}

#[test]
fn empty_oversized_or_unsupported_content_type_requests_fail_before_material() {
    denied_before_material(&Method::POST, "/messages", None, &headers(), b"");
    denied_before_material(
        &Method::POST,
        "/messages",
        None,
        &headers(),
        &vec![b'x'; MAX_REQUEST_BYTES + 1],
    );
    for content_type in [
        None,
        Some("text/plain"),
        Some("application/octet-stream"),
        Some("text/event-stream"),
        Some("application/json; charset=utf-16"),
        Some("application/json; charset=utf-8; charset=utf-8"),
    ] {
        let mut input = headers();
        input.remove(header::CONTENT_TYPE);
        if let Some(content_type) = content_type {
            input.insert(header::CONTENT_TYPE, HeaderValue::from_static(content_type));
        }
        denied_before_material(&Method::POST, "/messages", None, &input, BODY);
    }
}

#[test]
fn request_header_bounds_versions_duplicates_and_authority_selection_fail_closed() {
    for name in REQUEST_HEADERS {
        let mut input = headers();
        input.append(
            HeaderName::from_static(name),
            HeaderValue::from_static("duplicate"),
        );
        if *name == "anthropic-beta" {
            input.append("anthropic-beta", HeaderValue::from_static("second"));
        }
        denied_before_material(&Method::POST, "/messages", None, &input, BODY);
    }
    for name in [
        "anthropic-workspace-id",
        "anthropic-user-profile-id",
        "upgrade",
        "sec-websocket-key",
    ] {
        let mut input = headers();
        input.insert(
            HeaderName::from_static(name),
            HeaderValue::from_static("forbidden"),
        );
        denied_before_material(&Method::POST, "/messages", None, &input, BODY);
    }
    for version in [None, Some(""), Some("2024-01-01"), Some(" 2023-06-01")] {
        let mut input = headers();
        input.remove("anthropic-version");
        if let Some(version) = version {
            input.insert("anthropic-version", HeaderValue::from_static(version));
        }
        denied_before_material(&Method::POST, "/messages", None, &input, BODY);
    }
    let mut oversized = headers();
    oversized.insert(
        "x-ignored",
        HeaderValue::from_bytes(&vec![b'x'; MAX_HEADER_VALUE_BYTES + 1]).unwrap(),
    );
    denied_before_material(&Method::POST, "/messages", None, &oversized, BODY);
    let mut too_many = headers();
    for _ in 0..MAX_HEADERS {
        too_many.append("x-ignored", HeaderValue::from_static("value"));
    }
    denied_before_material(&Method::POST, "/messages", None, &too_many, BODY);
    let mut total = headers();
    for _ in 0..9 {
        total.append(
            "x-ignored",
            HeaderValue::from_bytes(&vec![b'x'; MAX_HEADER_VALUE_BYTES]).unwrap(),
        );
    }
    denied_before_material(&Method::POST, "/messages", None, &total, BODY);
}

#[test]
fn beta_feature_headers_are_finite_duplicate_free_tokens() {
    for beta in [
        "",
        "feature,",
        "feature,feature",
        "feature;other",
        "feature\tother",
        "feature=other",
    ] {
        let mut input = headers();
        input.insert("anthropic-beta", HeaderValue::from_static(beta));
        denied_before_material(&Method::POST, "/messages", None, &input, BODY);
    }
    let mut input = headers();
    let beta = (0..33)
        .map(|index| format!("feature-{index}"))
        .collect::<Vec<_>>()
        .join(",");
    input.insert("anthropic-beta", HeaderValue::from_str(&beta).unwrap());
    denied_before_material(&Method::POST, "/messages", None, &input, BODY);
}

#[test]
fn every_lease_coordinate_and_expiry_is_checked_before_borrowing_material() {
    for case in 0..15 {
        let mut lease = Lease::new(AnthropicOperation::Messages);
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
            10 => lease.grant.profile_revision = 0,
            11 => lease.material_generation = 0,
            12 => lease.permission.operation = BrokerOperationId::parse("count-tokens").unwrap(),
            13 => lease.permission.route = BrokerRouteId::parse("openai-api").unwrap(),
            _ => lease.grant.permissions.clear(),
        }
        let accessed = lease.accessed.clone();
        let error = AnthropicApiKeyAdapter::new()
            .unwrap()
            .prepare(lease, &Method::POST, "/messages", None, &headers(), BODY)
            .err();
        assert_eq!(
            error,
            Some(CredentialBrokerError::UnsupportedLease),
            "case {case}"
        );
        assert_eq!(accessed.get(), 0, "case {case}");
    }
}

#[test]
fn count_tokens_and_messages_permissions_are_not_interchangeable() {
    for (operation, path) in [
        (AnthropicOperation::Messages, "/messages/count_tokens"),
        (AnthropicOperation::CountTokens, "/messages"),
    ] {
        let lease = Lease::new(operation);
        let accessed = lease.accessed.clone();
        assert_eq!(
            AnthropicApiKeyAdapter::new()
                .unwrap()
                .prepare(lease, &Method::POST, path, None, &headers(), BODY)
                .err(),
            Some(CredentialBrokerError::UnsupportedLease)
        );
        assert_eq!(accessed.get(), 0);
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
        let mut lease = Lease::new(AnthropicOperation::Messages);
        lease.material = Zeroizing::new(material);
        let error = AnthropicApiKeyAdapter::new()
            .unwrap()
            .prepare(lease, &Method::POST, "/messages", None, &headers(), BODY)
            .err()
            .unwrap();
        assert_eq!(error, CredentialBrokerError::InvalidCredentialMaterial);
        assert!(!format!("{error:?}: {error}").contains("canary"));
    }
}

#[test]
fn nonidentity_duplicate_compound_and_malformed_codings_fail_before_response_release() {
    for values in [
        vec!["gzip"],
        vec!["br"],
        vec!["deflate"],
        vec!["zstd"],
        vec![""],
        vec![" "],
        vec!["identity,gzip"],
        vec!["identity,identity"],
        vec!["identity;q=1"],
        vec!["identity", "identity"],
        vec!["identity", "gzip"],
    ] {
        let mut upstream = response_headers("text/event-stream");
        for value in values {
            upstream.append(header::CONTENT_ENCODING, HeaderValue::from_static(value));
        }
        assert_eq!(
            prepared_response(AnthropicOperation::Messages)
                .begin(&upstream)
                .err(),
            Some(CredentialBrokerError::ResponseDenied)
        );
        let mut input = headers();
        for value in upstream.get_all(header::CONTENT_ENCODING) {
            input.append(header::CONTENT_ENCODING, value.clone());
        }
        denied_before_material(&Method::POST, "/messages", None, &input, BODY);
    }
    let mut upstream = response_headers("application/json");
    upstream.insert(
        header::CONTENT_ENCODING,
        HeaderValue::from_bytes(&[0xff]).unwrap(),
    );
    assert_eq!(
        prepared_response(AnthropicOperation::Messages)
            .begin(&upstream)
            .err(),
        Some(CredentialBrokerError::ResponseDenied)
    );
}

#[test]
fn absent_or_single_identity_encoding_and_utf8_json_or_sse_are_admitted() {
    for encoding in [None, Some("identity"), Some(" \tIdEnTiTy\t ")] {
        for content_type in [
            "application/json",
            "text/event-stream",
            "text/event-stream; charset=utf-8",
            "application/json; charset=\"UTF-8\"",
        ] {
            let mut upstream = response_headers(content_type);
            if let Some(encoding) = encoding {
                upstream.insert(header::CONTENT_ENCODING, HeaderValue::from_static(encoding));
            }
            let (headers, _) = prepared_response(AnthropicOperation::Messages)
                .begin(&upstream)
                .unwrap();
            assert!(!headers.contains_key(header::CONTENT_ENCODING));
            assert_eq!(headers[header::CONTENT_TYPE], content_type);
        }
    }
}

#[test]
fn response_allowlist_drops_opaque_errors_identity_cookies_and_redirects() {
    let mut upstream = response_headers("application/json");
    for name in [
        "x-error-json",
        "set-cookie",
        "authorization",
        "x-api-key",
        "location",
        "anthropic-organization-id",
        "anthropic-workspace-id",
        "x-unknown",
    ] {
        upstream.insert(
            HeaderName::from_static(name),
            HeaderValue::from_static("must-not-return"),
        );
    }
    for name in RESPONSE_HEADERS {
        if *name != "content-type" {
            upstream.insert(
                HeaderName::from_static(name),
                HeaderValue::from_bytes(KEY).unwrap(),
            );
        }
    }
    let (outbound, _) = prepared_response(AnthropicOperation::Messages)
        .begin(&upstream)
        .unwrap();
    assert_eq!(outbound.len(), RESPONSE_HEADERS.len());
    for name in RESPONSE_HEADERS {
        if *name != "content-type" {
            assert_eq!(outbound[*name], "[REDACTED]");
        }
    }
    assert!(!outbound.values().any(|value| value == "must-not-return"));
}

#[test]
fn response_duplicates_bounds_and_opaque_or_non_utf8_media_fail_closed() {
    for content_type in [
        "application/octet-stream",
        "application/json; charset=utf-16",
        "text/html",
        "application/json; charset=utf-8; charset=utf-8",
    ] {
        assert!(
            prepared_response(AnthropicOperation::Messages)
                .begin(&response_headers(content_type))
                .is_err()
        );
    }
    assert!(
        prepared_response(AnthropicOperation::Messages)
            .begin(&HeaderMap::new())
            .is_err()
    );
    assert!(
        prepared_response(AnthropicOperation::CountTokens)
            .begin(&response_headers("text/event-stream"))
            .is_err()
    );
    let mut duplicate = response_headers("application/json");
    duplicate.append("request-id", HeaderValue::from_static("one"));
    duplicate.append("request-id", HeaderValue::from_static("two"));
    assert!(
        prepared_response(AnthropicOperation::Messages)
            .begin(&duplicate)
            .is_err()
    );
    let mut oversized = response_headers("application/json");
    oversized.insert(
        "x-dropped",
        HeaderValue::from_bytes(&vec![b'x'; MAX_HEADER_VALUE_BYTES + 1]).unwrap(),
    );
    assert!(
        prepared_response(AnthropicOperation::Messages)
            .begin(&oversized)
            .is_err()
    );
}

fn reflections() -> Vec<Vec<u8>> {
    let raw = std::str::from_utf8(KEY).unwrap();
    let json = serde_json::to_string(raw).unwrap();
    let percent = url::form_urlencoded::byte_serialize(KEY).collect::<String>();
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
        KEY.to_vec(),
        STANDARD.encode(KEY).into_bytes(),
        STANDARD_NO_PAD.encode(KEY).into_bytes(),
        URL_SAFE.encode(KEY).into_bytes(),
        URL_SAFE_NO_PAD.encode(KEY).into_bytes(),
        percent.as_bytes().to_vec(),
        lower_percent,
        json.as_bytes()[1..json.len() - 1].to_vec(),
    ]
}

#[test]
fn raw_json_percent_and_base64_reflections_are_redacted_at_every_chunk_boundary() {
    for reflection in reflections() {
        for split in 0..=reflection.len() {
            let (_, mut response) = prepared_response(AnthropicOperation::Messages)
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
        headers.insert("request-id", HeaderValue::from_bytes(&reflection).unwrap());
        let (headers, _) = prepared_response(AnthropicOperation::CountTokens)
            .begin(&headers)
            .unwrap();
        assert_eq!(headers["request-id"], "[REDACTED]");
    }
}

#[test]
fn ordinary_sse_events_and_token_counts_survive_incremental_redaction_unchanged() {
    let sse = b"event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"id\":\"synthetic-message\"}}\n\nevent: ping\ndata: {\"type\":\"ping\"}\n\nevent: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"delta\":{\"type\":\"text_delta\",\"text\":\"hello\"}}\n\nevent: message_stop\ndata: {\"type\":\"message_stop\"}\n\n";
    for (operation, content_type, body) in [
        (
            AnthropicOperation::Messages,
            "text/event-stream",
            sse.as_slice(),
        ),
        (
            AnthropicOperation::CountTokens,
            "application/json",
            br#"{"input_tokens":42}"#.as_slice(),
        ),
    ] {
        let (_, mut response) = prepared_response(operation)
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

#[test]
fn response_body_ceiling_is_terminal_and_never_flushes_pending_material_after_failure() {
    let mut prepared = prepared_response(AnthropicOperation::Messages);
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
    assert_eq!(
        prepared_response(AnthropicOperation::CountTokens).max_body_bytes,
        MAX_COUNT_RESPONSE_BYTES
    );
}
