use std::collections::BTreeMap;
use std::time::{SystemTime, UNIX_EPOCH};

use av_credential_proxy::{
    CredentialSource, ProxyInjectionConfig, ProxyResponseMode, ProxyRouteConfig, RedactionSet,
    StreamingRedactor, ValidatedProxyRequest, build_target_url, is_websocket_attempt,
    prepare_credentials, prepare_outbound_headers, validate_proxy_request, validate_proxy_route,
};
use codewire_access::{CapabilitySlot, CredentialAuthKind, CredentialStatus};
use http::{HeaderMap, HeaderName, HeaderValue, Method};
use url::Url;

use crate::codex_oauth::CodexOAuthCredential;
use crate::{BrokerCredentialLease, CredentialBrokerError};

const ROUTE_NAME: &str = "openai-api";
const OPERATION_NAME: &str = "responses";
const PROVIDER_NAME: &str = "openai";
const CREDENTIAL_KEY: &str = "OPENAI_API_KEY";
const CODEX_OAUTH_ACCESS_TOKEN_KEY: &str = "CODEX_OAUTH_ACCESS_TOKEN";
const OPENAI_API_BASE_URL: &str = "https://api.openai.com/v1";
const CHATGPT_CODEX_BASE_URL: &str = "https://chatgpt.com/backend-api/codex";
const MAX_OPENAI_API_KEY_BYTES: usize = 1024;
const MAX_REQUEST_BYTES: usize = 4 * 1024 * 1024;
const MAX_RESPONSE_BYTES: usize = 256 * 1024 * 1024;

/// Immutable OpenAI Responses API-key policy used by the broker process.
pub struct OpenAiApiKeyAdapter {
    route: ProxyRouteConfig,
}

impl OpenAiApiKeyAdapter {
    /// Build and validate the compiled OpenAI route before accepting requests.
    pub fn new() -> Result<Self, CredentialBrokerError> {
        let route = openai_responses_route();
        validate_proxy_route(ROUTE_NAME, &route, false, false)
            .map_err(|_| CredentialBrokerError::InvalidProviderPolicy)?;
        Ok(Self { route })
    }

    /// Prepare exactly one credential-bearing upstream request.
    ///
    /// `path` is provider-relative and must currently be `/responses`. The
    /// authenticated listener will remove its non-secret environment and route
    /// prefix before invoking this method.
    pub fn prepare<L: BrokerCredentialLease>(
        &self,
        lease: L,
        method: &Method,
        path: &str,
        query: Option<&str>,
        headers: &HeaderMap,
        body: &[u8],
    ) -> Result<PreparedOpenAiRequest, CredentialBrokerError> {
        let request = self.validate_request(method, path, query, headers.clone(), body.to_vec())?;
        self.prepare_validated(lease, request)
    }

    /// Validate every guest-controlled field before asking a placement for a
    /// credential lease or reading protected storage.
    pub fn validate_request(
        &self,
        method: &Method,
        path: &str,
        query: Option<&str>,
        headers: HeaderMap,
        body: Vec<u8>,
    ) -> Result<ValidatedOpenAiRequest, CredentialBrokerError> {
        if is_websocket_attempt(&headers) {
            return Err(CredentialBrokerError::RequestDenied);
        }
        let request =
            validate_proxy_request(&self.route, path, query, method, &headers, body.len())
                .map_err(|_| CredentialBrokerError::RequestDenied)?;
        Ok(ValidatedOpenAiRequest {
            request,
            headers,
            body,
        })
    }

    /// Consume one already validated request and one exact authority lease.
    /// Protected material is borrowed only inside this method.
    pub fn prepare_validated<L: BrokerCredentialLease>(
        &self,
        lease: L,
        request: ValidatedOpenAiRequest,
    ) -> Result<PreparedOpenAiRequest, CredentialBrokerError> {
        validate_lease(&lease)?;
        let ValidatedOpenAiRequest {
            request,
            headers,
            body,
        } = request;
        let target = build_target_url(&self.route, &request)
            .map_err(|_| CredentialBrokerError::InvalidProviderPolicy)?;
        lease.with_material(|material| {
            if !valid_openai_api_key(material) {
                return Err(CredentialBrokerError::InvalidCredentialMaterial);
            }
            let material = std::str::from_utf8(material)
                .map_err(|_| CredentialBrokerError::InvalidCredentialMaterial)?;
            let source = OpenAiApiKey { material };
            let prepared = prepare_credentials(&self.route, &source, &body)
                .map_err(|_| CredentialBrokerError::InvalidCredentialMaterial)?;
            let headers = prepare_outbound_headers(&self.route, &headers, &prepared)
                .map_err(|_| CredentialBrokerError::RequestDenied)?;
            let (body, redaction) = prepared.into_body_and_redaction();
            let response = PreparedOpenAiResponse {
                allowed_headers: self
                    .route
                    .allowed_response_headers
                    .iter()
                    .map(|name| HeaderName::from_bytes(name.as_bytes()))
                    .collect::<Result<_, _>>()
                    .map_err(|_| CredentialBrokerError::InvalidProviderPolicy)?,
                max_body_bytes: self.route.max_response_bytes,
                redaction,
            };
            Ok(PreparedOpenAiRequest {
                method: Method::POST,
                target,
                headers,
                body,
                response,
            })
        })
    }
}

/// Immutable ChatGPT-backed Codex OAuth route used by the broker process.
///
/// The guest remains credential-free. Only the isolated broker parses the
/// protected OAuth bundle and constructs provider authorization headers.
pub(crate) struct OpenAiChatGptOAuthAdapter {
    route: ProxyRouteConfig,
}

impl OpenAiChatGptOAuthAdapter {
    pub(crate) fn new() -> Result<Self, CredentialBrokerError> {
        let route = chatgpt_codex_responses_route();
        validate_proxy_route(ROUTE_NAME, &route, false, false)
            .map_err(|_| CredentialBrokerError::InvalidProviderPolicy)?;
        Ok(Self { route })
    }

    /// Validate the authority lease before protected material is parsed.
    pub(crate) fn credential_from_lease<L: BrokerCredentialLease>(
        &self,
        lease: L,
    ) -> Result<CodexOAuthCredential, CredentialBrokerError> {
        validate_oauth_lease(&lease)?;
        lease.with_material(|material| {
            CodexOAuthCredential::parse(material)
                .map_err(|_| CredentialBrokerError::InvalidCredentialMaterial)
        })
    }

    pub(crate) fn prepare_credential(
        &self,
        credential: CodexOAuthCredential,
        request: ValidatedOpenAiRequest,
    ) -> Result<PreparedOpenAiRequest, CredentialBrokerError> {
        let ValidatedOpenAiRequest {
            request,
            headers,
            body,
        } = request;
        let target = build_target_url(&self.route, &request)
            .map_err(|_| CredentialBrokerError::InvalidProviderPolicy)?;
        let source = CodexOAuthAccessToken {
            material: credential.access_token(),
        };
        let prepared = prepare_credentials(&self.route, &source, &body)
            .map_err(|_| CredentialBrokerError::InvalidCredentialMaterial)?;
        let mut headers = prepare_outbound_headers(&self.route, &headers, &prepared)
            .map_err(|_| CredentialBrokerError::RequestDenied)?;
        let mut account_id = HeaderValue::from_str(credential.account_id())
            .map_err(|_| CredentialBrokerError::InvalidCredentialMaterial)?;
        account_id.set_sensitive(true);
        headers.insert("chatgpt-account-id", account_id);
        if credential.is_fedramp() {
            headers.insert("x-openai-fedramp", HeaderValue::from_static("true"));
        }
        let (body, prepared_redaction) = prepared.into_body_and_redaction();
        drop(prepared_redaction);
        let redaction = RedactionSet::new([
            credential.access_token().as_bytes(),
            credential.account_id().as_bytes(),
        ]);
        let response = PreparedOpenAiResponse {
            allowed_headers: response_header_names(&self.route)?,
            max_body_bytes: self.route.max_response_bytes,
            redaction,
        };
        Ok(PreparedOpenAiRequest {
            method: Method::POST,
            target,
            headers,
            body,
            response,
        })
    }
}

/// Credential-free request that has passed the immutable OpenAI route policy.
/// It deliberately carries no authority lease or prepared authorization.
#[derive(Clone)]
pub struct ValidatedOpenAiRequest {
    request: ValidatedProxyRequest,
    headers: HeaderMap,
    body: Vec<u8>,
}

impl Default for OpenAiApiKeyAdapter {
    fn default() -> Self {
        Self::new().expect("built-in OpenAI broker policy must be valid")
    }
}

/// A secret-bearing request plan that may exist only inside the broker
/// process. This type intentionally implements neither `Debug`, `Clone`, nor
/// serialization.
pub struct PreparedOpenAiRequest {
    method: Method,
    target: Url,
    headers: HeaderMap,
    body: Vec<u8>,
    response: PreparedOpenAiResponse,
}

impl PreparedOpenAiRequest {
    /// Consume the plan into the fields required by the broker-owned upstream
    /// HTTP transport and its response redactor.
    pub fn into_parts(self) -> (Method, Url, HeaderMap, Vec<u8>, PreparedOpenAiResponse) {
        (
            self.method,
            self.target,
            self.headers,
            self.body,
            self.response,
        )
    }
}

/// Response-header filter, byte ceiling, and credential redaction state for
/// one prepared OpenAI request. This type is non-cloneable and deliberately
/// has no `Debug` implementation.
pub struct PreparedOpenAiResponse {
    allowed_headers: Vec<HeaderName>,
    max_body_bytes: usize,
    redaction: RedactionSet,
}

impl PreparedOpenAiResponse {
    /// Filter and redact the upstream headers, then consume this policy into a
    /// bounded streaming body redactor.
    pub fn begin(
        self,
        upstream_headers: &HeaderMap,
    ) -> Result<(HeaderMap, OpenAiStreamingResponse), CredentialBrokerError> {
        let mut headers = HeaderMap::new();
        for name in &self.allowed_headers {
            let values = upstream_headers.get_all(name).iter().collect::<Vec<_>>();
            if values.len() > 1 {
                return Err(CredentialBrokerError::ResponseDenied);
            }
            for value in values {
                let value = self
                    .redaction
                    .redact_header(value)
                    .ok_or(CredentialBrokerError::ResponseDenied)?;
                headers.append(name.clone(), value);
            }
        }
        Ok((
            headers,
            OpenAiStreamingResponse {
                redactor: self.redaction.into_streaming(),
                max_body_bytes: self.max_body_bytes,
                received_body_bytes: 0,
                terminal_error: None,
            },
        ))
    }
}

/// Bounded streaming response redactor for one prepared provider operation.
/// Pending secret-pattern overlap is zeroized by the AV redactor on drop.
pub struct OpenAiStreamingResponse {
    redactor: StreamingRedactor,
    max_body_bytes: usize,
    received_body_bytes: usize,
    terminal_error: Option<CredentialBrokerError>,
}

impl OpenAiStreamingResponse {
    /// Admit and redact the next upstream body chunk.
    pub fn push(&mut self, chunk: &[u8]) -> Result<Vec<u8>, CredentialBrokerError> {
        if let Some(error) = self.terminal_error {
            return Err(error);
        }
        let Some(received_body_bytes) = self
            .received_body_bytes
            .checked_add(chunk.len())
            .filter(|received| *received <= self.max_body_bytes)
        else {
            self.terminal_error = Some(CredentialBrokerError::ResponseTooLarge);
            return Err(CredentialBrokerError::ResponseTooLarge);
        };
        self.received_body_bytes = received_body_bytes;
        Ok(self.redactor.push(chunk))
    }

    /// Finish redaction after the upstream body reaches EOF. Consuming the
    /// response prevents callers from appending bytes after a declared EOF.
    pub fn finish(mut self) -> Result<Vec<u8>, CredentialBrokerError> {
        if let Some(error) = self.terminal_error {
            return Err(error);
        }
        Ok(self.redactor.finish())
    }
}

struct OpenAiApiKey<'a> {
    material: &'a str,
}

struct CodexOAuthAccessToken<'a> {
    material: &'a str,
}

impl CredentialSource for CodexOAuthAccessToken<'_> {
    fn credential(&self, key: &str) -> Option<&str> {
        (key == CODEX_OAUTH_ACCESS_TOKEN_KEY).then_some(self.material)
    }
}

impl CredentialSource for OpenAiApiKey<'_> {
    fn credential(&self, key: &str) -> Option<&str> {
        (key == CREDENTIAL_KEY).then_some(self.material)
    }
}

fn validate_lease(lease: &impl BrokerCredentialLease) -> Result<(), CredentialBrokerError> {
    validate_current_lease(lease)?;
    let metadata = lease.credential_metadata();
    let grant = lease.grant();
    let permission = lease.permission();
    if metadata.provider.as_str() != PROVIDER_NAME
        || metadata.authentication_kind != CredentialAuthKind::ApiKey
        || grant.capability_slot != CapabilitySlot::codex()
        || grant.credential_id != metadata.id
        || permission.operation.as_str() != OPERATION_NAME
        || permission.route.as_str() != ROUTE_NAME
        || !grant.permissions.contains(permission)
    {
        return Err(CredentialBrokerError::UnsupportedLease);
    }
    Ok(())
}

fn validate_oauth_lease(lease: &impl BrokerCredentialLease) -> Result<(), CredentialBrokerError> {
    validate_current_lease(lease)?;
    let metadata = lease.credential_metadata();
    let grant = lease.grant();
    let permission = lease.permission();
    if metadata.provider.as_str() != PROVIDER_NAME
        || metadata.authentication_kind != CredentialAuthKind::OAuth
        || grant.capability_slot != CapabilitySlot::codex()
        || grant.credential_id != metadata.id
        || permission.operation.as_str() != OPERATION_NAME
        || permission.route.as_str() != ROUTE_NAME
        || !grant.permissions.contains(permission)
    {
        return Err(CredentialBrokerError::UnsupportedLease);
    }
    Ok(())
}

/// Placement reads may block after authority admission. Enforce both hard
/// deadlines when consuming the returned lease, before borrowing material.
fn validate_current_lease(lease: &impl BrokerCredentialLease) -> Result<(), CredentialBrokerError> {
    let metadata = lease.credential_metadata();
    let grant = lease.grant();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| CredentialBrokerError::UnsupportedLease)?
        .as_secs();
    if metadata.status != CredentialStatus::Active
        || metadata.revocation_generation == 0
        || metadata.revocation_generation != grant.credential_revocation_generation
        || metadata.expires_at_unix.is_some_and(|expiry| expiry <= now)
        || grant.expires_at_unix.is_some_and(|expiry| expiry <= now)
    {
        return Err(CredentialBrokerError::UnsupportedLease);
    }
    Ok(())
}

fn response_header_names(
    route: &ProxyRouteConfig,
) -> Result<Vec<HeaderName>, CredentialBrokerError> {
    route
        .allowed_response_headers
        .iter()
        .map(|name| HeaderName::from_bytes(name.as_bytes()))
        .collect::<Result<_, _>>()
        .map_err(|_| CredentialBrokerError::InvalidProviderPolicy)
}

fn valid_openai_api_key(material: &[u8]) -> bool {
    if material.is_empty() || material.len() > MAX_OPENAI_API_KEY_BYTES {
        return false;
    }
    let token_bytes = material
        .iter()
        .position(|byte| *byte == b'=')
        .unwrap_or(material.len());
    token_bytes > 0
        && material[..token_bytes].iter().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~' | b'+' | b'/')
        })
        && material[token_bytes..].iter().all(|byte| *byte == b'=')
}

fn openai_responses_route() -> ProxyRouteConfig {
    ProxyRouteConfig {
        profile: "codewire-openai-api-key".to_owned(),
        base_url: OPENAI_API_BASE_URL.to_owned(),
        secret_key: String::new(),
        header: String::new(),
        header_prefix: String::new(),
        injection: Some(ProxyInjectionConfig::Bearer {
            secret_key: CREDENTIAL_KEY.to_owned(),
        }),
        body_substitutions: BTreeMap::new(),
        allowed_methods: vec!["POST".to_owned()],
        allowed_exact_paths: vec!["/responses".to_owned()],
        allowed_path_prefixes: Vec::new(),
        allowed_request_headers: vec![
            "accept".to_owned(),
            "content-type".to_owned(),
            "openai-beta".to_owned(),
            "originator".to_owned(),
            "session-id".to_owned(),
            "thread-id".to_owned(),
            "x-client-request-id".to_owned(),
            "x-codex-beta-features".to_owned(),
            "x-codex-inference-call-id".to_owned(),
            "x-codex-installation-id".to_owned(),
            "x-codex-parent-thread-id".to_owned(),
            "x-codex-routing-hint".to_owned(),
            "x-codex-sandbox".to_owned(),
            "x-codex-turn-state".to_owned(),
            "x-codex-turn-metadata".to_owned(),
            "x-codex-window-id".to_owned(),
            "x-oai-attestation".to_owned(),
            "x-openai-internal-codex-responses-lite".to_owned(),
            "x-openai-memgen-request".to_owned(),
            "x-openai-subagent".to_owned(),
        ],
        allowed_response_headers: vec![
            "cf-ray".to_owned(),
            "content-type".to_owned(),
            "openai-processing-ms".to_owned(),
            "openai-version".to_owned(),
            "openai-model".to_owned(),
            "retry-after".to_owned(),
            "x-codex-active-limit".to_owned(),
            "x-codex-credits-balance".to_owned(),
            "x-codex-credits-has-credits".to_owned(),
            "x-codex-credits-unlimited".to_owned(),
            "x-codex-primary-reset-at".to_owned(),
            "x-codex-primary-used-percent".to_owned(),
            "x-codex-primary-window-minutes".to_owned(),
            "x-codex-promo-message".to_owned(),
            "x-codex-rate-limit-reached-type".to_owned(),
            "x-codex-safety-buffering-enabled".to_owned(),
            "x-codex-safety-buffering-faster-model".to_owned(),
            "x-codex-secondary-primary-reset-at".to_owned(),
            "x-codex-secondary-primary-used-percent".to_owned(),
            "x-codex-secondary-primary-window-minutes".to_owned(),
            "x-codex-secondary-reset-at".to_owned(),
            "x-codex-secondary-used-percent".to_owned(),
            "x-codex-secondary-window-minutes".to_owned(),
            "x-codex-turn-state".to_owned(),
            "x-models-etag".to_owned(),
            "x-oai-request-id".to_owned(),
            "x-openai-authorization-error".to_owned(),
            "x-openai-model".to_owned(),
            "x-reasoning-included".to_owned(),
            "x-request-id".to_owned(),
        ],
        allowed_query_parameters: Vec::new(),
        allowed_content_types: vec!["application/json".to_owned()],
        max_body_bytes: MAX_REQUEST_BYTES,
        response_mode: ProxyResponseMode::Streaming,
        max_response_bytes: MAX_RESPONSE_BYTES,
        websocket: None,
    }
}

fn chatgpt_codex_responses_route() -> ProxyRouteConfig {
    let mut route = openai_responses_route();
    route.profile = "codewire-codex-chatgpt-oauth".to_owned();
    route.base_url = CHATGPT_CODEX_BASE_URL.to_owned();
    route.injection = Some(ProxyInjectionConfig::Bearer {
        secret_key: CODEX_OAUTH_ACCESS_TOKEN_KEY.to_owned(),
    });
    route
}

#[cfg(test)]
mod tests {
    use std::{
        cell::Cell,
        collections::{BTreeMap, BTreeSet},
        rc::Rc,
    };

    use codewire_access::{
        AccessProfileName, BrokerOperationId, BrokerRouteId, CapabilityPolicy, CredentialAuthKind,
        EnvironmentAccessBinding, EnvironmentId, GrantPermission, ProviderCatalog,
        ProviderDefinition, ProviderId,
    };
    use codewire_local_credentials::{
        CredentialOperationLease, CredentialOperationLeaseRequest, LocalCredentialAuthority,
        NewCredential,
    };
    use codewire_protected_store::{EphemeralProtectedStore, ProtectedValue};
    use http::{HeaderValue, header};
    use serde_json::json;
    use tempfile::TempDir;

    use super::*;
    use crate::CanonicalCodexOAuthBundle;

    const SYNTHETIC_KEY: &str = "CW_TEST_OPENAI_VALUE_123";

    fn jwt(payload: serde_json::Value) -> String {
        use base64::Engine as _;

        let header = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(br#"{"alg":"none"}"#);
        let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(serde_json::to_vec(&payload).expect("JWT payload"));
        format!("{header}.{payload}.synthetic-signature")
    }

    fn oauth_bundle(fedramp: bool) -> CanonicalCodexOAuthBundle {
        let source = serde_json::to_vec(&json!({
            "auth_mode": "chatgpt",
            "OPENAI_API_KEY": null,
            "tokens": {
                "id_token": jwt(json!({
                    "email": "developer@example.test",
                    "https://api.openai.com/auth": {
                        "chatgpt_account_id": "account-work",
                        "chatgpt_account_is_fedramp": fedramp
                    }
                })),
                "access_token": "synthetic.oauth.access-token",
                "refresh_token": "synthetic-oauth-refresh-token",
                "account_id": "account-work"
            }
        }))
        .expect("Codex auth JSON");
        let imported = crate::import_codex_auth_json(&source).expect("Codex OAuth import");
        imported.into_parts().0
    }

    fn provider(value: &str) -> ProviderId {
        ProviderId::parse(value).expect("provider ID")
    }

    fn catalog(provider_id: &str, authentication_kind: CredentialAuthKind) -> ProviderCatalog {
        ProviderCatalog::from_definitions([ProviderDefinition {
            id: provider(provider_id),
            authentication_kinds: BTreeSet::from([authentication_kind]),
            capabilities: BTreeMap::from([(
                CapabilitySlot::codex(),
                CapabilityPolicy {
                    authentication_kinds: BTreeSet::from([authentication_kind]),
                    permissions: BTreeSet::from([GrantPermission {
                        operation: BrokerOperationId::parse(OPERATION_NAME).expect("operation"),
                        route: BrokerRouteId::parse(ROUTE_NAME).expect("route"),
                    }]),
                },
            )]),
        }])
        .expect("provider catalog")
    }

    fn lease(
        provider_id: &str,
        authentication_kind: CredentialAuthKind,
        material: &[u8],
    ) -> CredentialOperationLease {
        let temp = TempDir::new().expect("authority root");
        let authority = LocalCredentialAuthority::open(
            &temp.path().join("authority"),
            EphemeralProtectedStore::default(),
            catalog(provider_id, authentication_kind),
        )
        .expect("open authority");
        let credential = authority
            .add_credential(
                NewCredential {
                    provider: provider(provider_id),
                    authentication_kind,
                    display_name: "synthetic".to_owned(),
                    account_hint: None,
                    expires_at_unix: None,
                },
                ProtectedValue::from_slice(material).expect("synthetic material"),
            )
            .expect("add credential");
        let profile = authority
            .create_profile(
                AccessProfileName::parse("test").expect("profile name"),
                BTreeMap::from([(CapabilitySlot::codex(), credential.metadata.id)]),
            )
            .expect("create profile");
        let environment_id = EnvironmentId::parse("environment-test").expect("environment ID");
        authority
            .create_environment_access_binding(EnvironmentAccessBinding {
                environment_id: environment_id.clone(),
                profile_id: profile.profile.id,
                profile_revision: profile.profile.revision,
            })
            .expect("bind profile");
        authority
            .lease_environment_credential_operation(&CredentialOperationLeaseRequest {
                environment_id,
                environment_generation: 7,
                capability_slot: CapabilitySlot::codex(),
                operation: BrokerOperationId::parse(OPERATION_NAME).expect("operation"),
                route: BrokerRouteId::parse(ROUTE_NAME).expect("route"),
            })
            .expect("operation lease")
    }

    fn request_headers() -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::ACCEPT,
            HeaderValue::from_static("text/event-stream"),
        );
        headers.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        );
        headers.insert(
            "x-codex-turn-metadata",
            HeaderValue::from_static("synthetic-metadata"),
        );
        headers.insert(
            "x-codex-beta-features",
            HeaderValue::from_static("synthetic-feature"),
        );
        headers.insert(
            "x-client-request-id",
            HeaderValue::from_static("synthetic-request"),
        );
        headers.insert("session-id", HeaderValue::from_static("synthetic-session"));
        headers.insert("thread-id", HeaderValue::from_static("synthetic-thread"));
        headers.insert(
            "x-codex-turn-state",
            HeaderValue::from_static("synthetic-turn-state"),
        );
        headers.insert(
            "x-codex-routing-hint",
            HeaderValue::from_static("synthetic-routing-hint"),
        );
        headers.insert(
            "x-openai-internal-codex-responses-lite",
            HeaderValue::from_static("true"),
        );
        headers.insert("x-openai-memgen-request", HeaderValue::from_static("true"));
        headers
    }

    struct TrackingLease {
        inner: CredentialOperationLease,
        material_accessed: Rc<Cell<bool>>,
    }

    impl BrokerCredentialLease for TrackingLease {
        fn credential_metadata(&self) -> &codewire_access::CredentialMetadata {
            &self.inner.credential.metadata
        }

        fn grant(&self) -> &codewire_access::DerivedGrant {
            &self.inner.grant
        }

        fn permission(&self) -> &GrantPermission {
            &self.inner.permission
        }

        fn material_generation(&self) -> u64 {
            self.inner.material_generation()
        }

        fn with_material<T>(self, operation: impl FnOnce(&[u8]) -> T) -> T {
            self.material_accessed.set(true);
            self.inner.with_material(operation)
        }
    }

    #[test]
    fn rejects_stale_or_expired_leases_before_borrowing_material() {
        for kind in [CredentialAuthKind::ApiKey, CredentialAuthKind::OAuth] {
            for case in [
                "credential expiry",
                "grant expiry",
                "revocation",
                "generation",
            ] {
                let mut inner = lease("openai", kind, SYNTHETIC_KEY.as_bytes());
                match case {
                    "credential expiry" => inner.credential.metadata.expires_at_unix = Some(0),
                    "grant expiry" => inner.grant.expires_at_unix = Some(0),
                    "revocation" => inner.credential.metadata.status = CredentialStatus::Revoked,
                    "generation" => inner.grant.credential_revocation_generation += 1,
                    _ => unreachable!(),
                }
                let material_accessed = Rc::new(Cell::new(false));
                let lease = TrackingLease {
                    inner,
                    material_accessed: Rc::clone(&material_accessed),
                };
                let error = match kind {
                    CredentialAuthKind::ApiKey => OpenAiApiKeyAdapter::new()
                        .expect("adapter")
                        .prepare(
                            lease,
                            &Method::POST,
                            "/responses",
                            None,
                            &request_headers(),
                            br#"{"model":"synthetic-model","input":"hello"}"#,
                        )
                        .err(),
                    CredentialAuthKind::OAuth => OpenAiChatGptOAuthAdapter::new()
                        .expect("adapter")
                        .credential_from_lease(lease)
                        .err(),
                    _ => unreachable!(),
                };
                assert_eq!(
                    error,
                    Some(CredentialBrokerError::UnsupportedLease),
                    "{case}"
                );
                assert!(
                    !material_accessed.get(),
                    "{case} borrowed protected material"
                );
            }
        }
    }

    #[test]
    fn prepares_one_strict_openai_responses_request() {
        let mut headers = request_headers();
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("Bearer guest-controlled"),
        );
        headers.insert(
            header::COOKIE,
            HeaderValue::from_static("guest-cookie=blocked"),
        );
        headers.insert(
            header::PROXY_AUTHORIZATION,
            HeaderValue::from_static("Basic guest-controlled"),
        );
        headers.insert(header::HOST, HeaderValue::from_static("guest.invalid"));
        headers.insert(header::CONNECTION, HeaderValue::from_static("keep-alive"));
        headers.insert(
            header::TRANSFER_ENCODING,
            HeaderValue::from_static("chunked"),
        );
        headers.insert(header::CONTENT_LENGTH, HeaderValue::from_static("999999"));
        headers.insert(
            header::USER_AGENT,
            HeaderValue::from_static("synthetic-codex/1.0"),
        );
        let body = br#"{"model":"synthetic-model","input":"hello"}"#;
        let prepared = OpenAiApiKeyAdapter::new()
            .expect("adapter")
            .prepare(
                lease(
                    "openai",
                    CredentialAuthKind::ApiKey,
                    SYNTHETIC_KEY.as_bytes(),
                ),
                &Method::POST,
                "/responses",
                None,
                &headers,
                body,
            )
            .expect("prepare request");
        let (method, target, headers, prepared_body, response) = prepared.into_parts();

        assert_eq!(method, Method::POST);
        assert_eq!(target.as_str(), "https://api.openai.com/v1/responses");
        assert_eq!(prepared_body, body);
        let authorization = headers
            .get(header::AUTHORIZATION)
            .expect("injected authorization");
        assert_eq!(
            authorization,
            HeaderValue::from_static("Bearer CW_TEST_OPENAI_VALUE_123")
        );
        assert!(authorization.is_sensitive());
        for blocked in [
            header::COOKIE,
            header::PROXY_AUTHORIZATION,
            header::HOST,
            header::CONNECTION,
            header::TRANSFER_ENCODING,
            header::CONTENT_LENGTH,
            header::USER_AGENT,
        ] {
            assert!(!headers.contains_key(blocked));
        }
        assert_eq!(
            headers.get("x-codex-turn-metadata"),
            Some(&HeaderValue::from_static("synthetic-metadata"))
        );
        for (name, value) in [
            ("x-codex-beta-features", "synthetic-feature"),
            ("x-client-request-id", "synthetic-request"),
            ("session-id", "synthetic-session"),
            ("thread-id", "synthetic-thread"),
            ("x-codex-turn-state", "synthetic-turn-state"),
            ("x-codex-routing-hint", "synthetic-routing-hint"),
            ("x-openai-internal-codex-responses-lite", "true"),
            ("x-openai-memgen-request", "true"),
        ] {
            assert_eq!(
                headers.get(name).and_then(|value| value.to_str().ok()),
                Some(value)
            );
        }
        let mut upstream_headers = HeaderMap::new();
        upstream_headers.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("text/event-stream"),
        );
        upstream_headers.insert(
            "x-request-id",
            HeaderValue::from_static("CW_TEST_OPENAI_VALUE_123"),
        );
        upstream_headers.insert(
            header::SET_COOKIE,
            HeaderValue::from_static("value=CW_TEST_OPENAI_VALUE_123"),
        );
        let (response_headers, mut response) =
            response.begin(&upstream_headers).expect("begin response");
        assert_eq!(
            response_headers.get("x-request-id"),
            Some(&HeaderValue::from_static("[REDACTED]"))
        );
        assert!(!response_headers.contains_key(header::SET_COOKIE));

        let mut output = response
            .push(b"upstream reflected CW_TEST_OPENAI_")
            .expect("first response chunk");
        output.extend(
            response
                .push(b"VALUE_123 and Bearer CW_TEST_OPENAI_VALUE_123")
                .expect("second response chunk"),
        );
        output.extend(response.finish().expect("finish response"));
        assert_eq!(output, b"upstream reflected [REDACTED] and [REDACTED]");
    }

    #[test]
    fn prepares_chatgpt_codex_oauth_without_trusting_guest_auth_headers() {
        let bundle = oauth_bundle(true);
        let mut headers = request_headers();
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("Bearer guest-controlled"),
        );
        headers.insert(
            "chatgpt-account-id",
            HeaderValue::from_static("guest-account"),
        );
        headers.insert("x-openai-fedramp", HeaderValue::from_static("false"));
        let request = OpenAiApiKeyAdapter::new()
            .expect("request validator")
            .validate_request(
                &Method::POST,
                "/responses",
                None,
                headers,
                br#"{"input":"hello"}"#.to_vec(),
            )
            .expect("validated request");
        let adapter = OpenAiChatGptOAuthAdapter::new().expect("OAuth adapter");
        let credential = adapter
            .credential_from_lease(lease(
                "openai",
                CredentialAuthKind::OAuth,
                bundle.as_bytes(),
            ))
            .expect("OAuth lease");
        let prepared = adapter
            .prepare_credential(credential, request)
            .expect("prepared OAuth request");
        let (method, target, headers, body, response) = prepared.into_parts();

        assert_eq!(method, Method::POST);
        assert_eq!(
            target.as_str(),
            "https://chatgpt.com/backend-api/codex/responses"
        );
        assert_eq!(body, br#"{"input":"hello"}"#);
        let authorization = headers
            .get(header::AUTHORIZATION)
            .expect("broker authorization");
        assert_eq!(
            authorization,
            HeaderValue::from_static("Bearer synthetic.oauth.access-token")
        );
        assert!(authorization.is_sensitive());
        let account = headers
            .get("chatgpt-account-id")
            .expect("broker account header");
        assert_eq!(account, HeaderValue::from_static("account-work"));
        assert!(account.is_sensitive());
        assert_eq!(
            headers.get("x-openai-fedramp"),
            Some(&HeaderValue::from_static("true"))
        );

        let mut upstream_headers = HeaderMap::new();
        upstream_headers.insert(
            "x-request-id",
            HeaderValue::from_static("synthetic.oauth.access-token"),
        );
        upstream_headers.insert(
            "x-codex-turn-state",
            HeaderValue::from_static("state-for-account-work"),
        );
        upstream_headers.insert(
            "x-openai-authorization-error",
            HeaderValue::from_static("token_expired"),
        );
        upstream_headers.insert(
            "x-oai-request-id",
            HeaderValue::from_static("request-for-account-work"),
        );
        upstream_headers.insert("cf-ray", HeaderValue::from_static("ray-for-account-work"));
        upstream_headers.insert(
            "x-error-json",
            HeaderValue::from_static("ZXJyb3ItZm9yLWFjY291bnQtd29yaw=="),
        );
        upstream_headers.insert("x-codex-active-limit", HeaderValue::from_static("codex"));
        let (headers, mut response) = response.begin(&upstream_headers).expect("OAuth response");
        assert_eq!(
            headers.get("x-request-id"),
            Some(&HeaderValue::from_static("[REDACTED]"))
        );
        assert_eq!(
            headers.get("x-codex-turn-state"),
            Some(&HeaderValue::from_static("state-for-[REDACTED]"))
        );
        for (name, value) in [
            ("x-openai-authorization-error", "token_expired"),
            ("x-oai-request-id", "request-for-[REDACTED]"),
            ("cf-ray", "ray-for-[REDACTED]"),
            ("x-codex-active-limit", "codex"),
        ] {
            assert_eq!(
                headers.get(name).and_then(|value| value.to_str().ok()),
                Some(value)
            );
        }
        assert!(!headers.contains_key("x-error-json"));
        let mut output = response
            .push(b"reflected account-work and synthetic.oauth.")
            .expect("first chunk");
        output.extend(response.push(b"access-token").expect("second chunk"));
        output.extend(response.finish().expect("finish response"));
        assert_eq!(output, b"reflected [REDACTED] and [REDACTED]");
    }

    #[test]
    fn rejects_wrong_provider_or_authentication_kind() {
        let adapter = OpenAiApiKeyAdapter::new().expect("adapter");
        let headers = request_headers();
        let body = br#"{"input":"hello"}"#;

        for lease in [
            lease(
                "other",
                CredentialAuthKind::ApiKey,
                SYNTHETIC_KEY.as_bytes(),
            ),
            lease(
                "openai",
                CredentialAuthKind::AccessToken,
                SYNTHETIC_KEY.as_bytes(),
            ),
        ] {
            assert!(matches!(
                adapter.prepare(lease, &Method::POST, "/responses", None, &headers, body,),
                Err(CredentialBrokerError::UnsupportedLease)
            ));
        }
    }

    #[test]
    fn rechecks_the_authority_lease_scope_before_material_access() {
        let adapter = OpenAiApiKeyAdapter::new().expect("adapter");
        let headers = request_headers();
        let body = br#"{"input":"hello"}"#;

        let mut wrong_route = lease(
            "openai",
            CredentialAuthKind::ApiKey,
            SYNTHETIC_KEY.as_bytes(),
        );
        wrong_route.permission.route = BrokerRouteId::parse("other-route").expect("route");
        let material_accessed = Rc::new(Cell::new(false));
        assert!(matches!(
            adapter.prepare(
                TrackingLease {
                    inner: wrong_route,
                    material_accessed: Rc::clone(&material_accessed),
                },
                &Method::POST,
                "/responses",
                None,
                &headers,
                body,
            ),
            Err(CredentialBrokerError::UnsupportedLease)
        ));
        assert!(!material_accessed.get());

        let mut wrong_slot = lease(
            "openai",
            CredentialAuthKind::ApiKey,
            SYNTHETIC_KEY.as_bytes(),
        );
        wrong_slot.grant.capability_slot = CapabilitySlot::github();
        assert!(matches!(
            adapter.prepare(
                wrong_slot,
                &Method::POST,
                "/responses",
                None,
                &headers,
                body,
            ),
            Err(CredentialBrokerError::UnsupportedLease)
        ));

        let mut wrong_operation = lease(
            "openai",
            CredentialAuthKind::ApiKey,
            SYNTHETIC_KEY.as_bytes(),
        );
        wrong_operation.permission.operation =
            BrokerOperationId::parse("other-operation").expect("operation");
        assert!(matches!(
            adapter.prepare(
                wrong_operation,
                &Method::POST,
                "/responses",
                None,
                &headers,
                body,
            ),
            Err(CredentialBrokerError::UnsupportedLease)
        ));

        let mut missing_permission = lease(
            "openai",
            CredentialAuthKind::ApiKey,
            SYNTHETIC_KEY.as_bytes(),
        );
        missing_permission.grant.permissions.clear();
        assert!(matches!(
            adapter.prepare(
                missing_permission,
                &Method::POST,
                "/responses",
                None,
                &headers,
                body,
            ),
            Err(CredentialBrokerError::UnsupportedLease)
        ));

        let mut wrong_credential = lease(
            "openai",
            CredentialAuthKind::ApiKey,
            SYNTHETIC_KEY.as_bytes(),
        );
        wrong_credential.grant.credential_id =
            codewire_access::CredentialId::parse("different-credential").expect("credential ID");
        assert!(matches!(
            adapter.prepare(
                wrong_credential,
                &Method::POST,
                "/responses",
                None,
                &headers,
                body,
            ),
            Err(CredentialBrokerError::UnsupportedLease)
        ));
    }

    #[test]
    fn rejects_method_path_query_content_type_websocket_and_oversize_body() {
        let adapter = OpenAiApiKeyAdapter::new().expect("adapter");
        let body = br#"{"input":"hello"}"#;
        let cases = [
            (
                Method::GET,
                "/responses",
                None,
                request_headers(),
                body.as_slice(),
            ),
            (
                Method::POST,
                "/models",
                None,
                request_headers(),
                body.as_slice(),
            ),
            (
                Method::POST,
                "/responses",
                Some("api-version=untrusted"),
                request_headers(),
                body.as_slice(),
            ),
        ];
        for (method, path, query, headers, body) in cases {
            assert!(matches!(
                adapter.prepare(
                    lease(
                        "openai",
                        CredentialAuthKind::ApiKey,
                        SYNTHETIC_KEY.as_bytes()
                    ),
                    &method,
                    path,
                    query,
                    &headers,
                    body,
                ),
                Err(CredentialBrokerError::RequestDenied)
            ));
        }

        let mut wrong_content_type = request_headers();
        wrong_content_type.insert(header::CONTENT_TYPE, HeaderValue::from_static("text/plain"));
        assert!(matches!(
            adapter.prepare(
                lease(
                    "openai",
                    CredentialAuthKind::ApiKey,
                    SYNTHETIC_KEY.as_bytes()
                ),
                &Method::POST,
                "/responses",
                None,
                &wrong_content_type,
                body,
            ),
            Err(CredentialBrokerError::RequestDenied)
        ));

        let mut websocket = request_headers();
        websocket.insert(header::UPGRADE, HeaderValue::from_static("websocket"));
        assert!(matches!(
            adapter.prepare(
                lease(
                    "openai",
                    CredentialAuthKind::ApiKey,
                    SYNTHETIC_KEY.as_bytes()
                ),
                &Method::POST,
                "/responses",
                None,
                &websocket,
                body,
            ),
            Err(CredentialBrokerError::RequestDenied)
        ));

        let oversized = vec![b'x'; MAX_REQUEST_BYTES + 1];
        assert!(matches!(
            adapter.prepare(
                lease(
                    "openai",
                    CredentialAuthKind::ApiKey,
                    SYNTHETIC_KEY.as_bytes()
                ),
                &Method::POST,
                "/responses",
                None,
                &request_headers(),
                &oversized,
            ),
            Err(CredentialBrokerError::RequestDenied)
        ));
    }

    #[test]
    fn invalid_material_fails_with_a_fixed_redacted_error() {
        let result = OpenAiApiKeyAdapter::new().expect("adapter").prepare(
            lease("openai", CredentialAuthKind::ApiKey, b"invalid\nkey"),
            &Method::POST,
            "/responses",
            None,
            &request_headers(),
            br#"{"input":"hello"}"#,
        );
        let error = match result {
            Err(error) => error,
            Ok(_) => panic!("invalid header material must fail"),
        };
        assert_eq!(error, CredentialBrokerError::InvalidCredentialMaterial);
        let rendered = format!("{error:?} {error}");
        assert!(!rendered.contains("invalid\nkey"));
        assert!(!rendered.contains("Bearer"));

        let valid_bearer_grammar = "CW.TEST~OPENAI+VALUE/123==";
        assert!(
            OpenAiApiKeyAdapter::new()
                .expect("adapter")
                .prepare(
                    lease(
                        "openai",
                        CredentialAuthKind::ApiKey,
                        valid_bearer_grammar.as_bytes(),
                    ),
                    &Method::POST,
                    "/responses",
                    None,
                    &request_headers(),
                    br#"{"input":"hello"}"#,
                )
                .is_ok()
        );
    }

    #[test]
    fn response_byte_ceiling_fails_closed() {
        let prepared = OpenAiApiKeyAdapter::new()
            .expect("adapter")
            .prepare(
                lease(
                    "openai",
                    CredentialAuthKind::ApiKey,
                    SYNTHETIC_KEY.as_bytes(),
                ),
                &Method::POST,
                "/responses",
                None,
                &request_headers(),
                br#"{"input":"hello"}"#,
            )
            .expect("prepare request");
        let (_, _, _, _, mut response) = prepared.into_parts();
        response.max_body_bytes = 4;
        let (_, mut response) = response.begin(&HeaderMap::new()).expect("begin response");
        assert_eq!(
            response.push(b"1234").expect("bounded chunk"),
            Vec::<u8>::new()
        );
        assert_eq!(
            response.push(b"5"),
            Err(CredentialBrokerError::ResponseTooLarge)
        );
        assert_eq!(
            response.push(b"1"),
            Err(CredentialBrokerError::ResponseTooLarge)
        );
        assert_eq!(
            response.finish(),
            Err(CredentialBrokerError::ResponseTooLarge)
        );
    }

    #[test]
    fn duplicate_allowed_response_headers_fail_closed() {
        let prepared = OpenAiApiKeyAdapter::new()
            .expect("adapter")
            .prepare(
                lease(
                    "openai",
                    CredentialAuthKind::ApiKey,
                    SYNTHETIC_KEY.as_bytes(),
                ),
                &Method::POST,
                "/responses",
                None,
                &request_headers(),
                br#"{"input":"hello"}"#,
            )
            .expect("prepare request");
        let (_, _, _, _, response) = prepared.into_parts();
        let mut upstream_headers = HeaderMap::new();
        upstream_headers.append(
            header::CONTENT_TYPE,
            HeaderValue::from_static("text/event-stream"),
        );
        upstream_headers.append(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        );

        assert!(matches!(
            response.begin(&upstream_headers),
            Err(CredentialBrokerError::ResponseDenied)
        ));
    }
}
