mod connect_smoke;
mod environment_session;
mod exec_file;

use std::env;
use std::time::Duration;

use base64::Engine as _;
use buffa::Message as _;
use codewire_proto::google::rpc::{BadRequest, ErrorInfo, RetryInfo};
use connectrpc::client::ClientConfig;
use connectrpc::{CodecFormat, ConnectError, ErrorCode};
use reqwest::header::COOKIE;
use reqwest::{Client, Method, StatusCode};
use serde_json::{Map, Value};

const SESSION_COOKIE: &str = "codewire.session_token";
pub(super) const PRIMARY_ORG: &str = "org_apikey_contract_1";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum KubeMode {
    Configured,
    Unconfigured,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Scope {
    Complete,
    RuntimeBoundary,
}

#[derive(Clone, Copy)]
pub(super) enum Auth {
    None,
    GlobalAdmin,
    Admin,
    User,
}

#[derive(Debug)]
pub(super) struct WireResponse {
    pub status: StatusCode,
    pub headers: reqwest::header::HeaderMap,
    pub body: Vec<u8>,
}

impl WireResponse {
    pub fn assert_status(&self, expected: StatusCode, label: &str) {
        assert_eq!(
            self.status,
            expected,
            "{label}: body={:?}",
            String::from_utf8_lossy(&self.body)
        );
    }

    pub fn json(&self) -> Value {
        serde_json::from_slice(&self.body).unwrap_or_else(|error| {
            panic!(
                "decode HTTP {} body {:?} as JSON: {error}",
                self.status,
                String::from_utf8_lossy(&self.body)
            )
        })
    }
}

pub(super) struct Harness {
    pub base_url: String,
    pub global_admin_token: String,
    pub admin_token: String,
    pub user_token: String,
    pub kube_mode: KubeMode,
    scope: Scope,
    client: Client,
}

impl Harness {
    pub fn from_env() -> Self {
        assert_eq!(
            required_env("ORCHESTRATION_SEEDED"),
            "1",
            "ORCHESTRATION_SEEDED must declare the deterministic fixture"
        );
        let kube_mode = match required_env("ORCHESTRATION_KUBE_MODE").as_str() {
            "configured" => KubeMode::Configured,
            "unconfigured" => KubeMode::Unconfigured,
            value => {
                panic!("ORCHESTRATION_KUBE_MODE={value:?}, expected configured or unconfigured")
            }
        };
        let scope = match env::var("ORCHESTRATION_CONTRACT_SCOPE")
            .as_deref()
            .unwrap_or("complete")
        {
            "complete" => Scope::Complete,
            "runtime" => Scope::RuntimeBoundary,
            value => panic!("ORCHESTRATION_CONTRACT_SCOPE={value:?}, expected complete or runtime"),
        };
        Self {
            base_url: required_env("ORCHESTRATION_BASE_URL")
                .trim_end_matches('/')
                .to_owned(),
            global_admin_token: required_env("ORCHESTRATION_GLOBAL_ADMIN_SESSION_TOKEN"),
            admin_token: required_env("ORCHESTRATION_ADMIN_SESSION_TOKEN"),
            user_token: required_env("ORCHESTRATION_USER_SESSION_TOKEN"),
            kube_mode,
            scope,
            client: Client::builder()
                .timeout(Duration::from_secs(30))
                .pool_max_idle_per_host(0)
                .build()
                .expect("build orchestration contract HTTP client"),
        }
    }

    pub async fn run(&self) {
        if self.scope == Scope::RuntimeBoundary {
            connect_smoke::assert_detection_unconfigured(self).await;
            exec_file::assert_runtime_boundaries(self).await;
            return;
        }

        self.assert_health().await;
        connect_smoke::run(self).await;
        environment_session::run(self).await;
        exec_file::run(self).await;
    }

    async fn assert_health(&self) {
        for path in ["/healthz", "/readyz"] {
            self.request(Method::GET, path, Auth::None, None)
                .await
                .assert_status(StatusCode::OK, path);
        }
    }

    pub async fn connect_json(
        &self,
        service: &str,
        method: &str,
        body: Value,
        auth: Auth,
    ) -> WireResponse {
        self.request(
            Method::POST,
            &format!("/{service}/{method}"),
            auth,
            Some(body),
        )
        .await
    }

    pub async fn rest(
        &self,
        method: Method,
        path: &str,
        body: Option<Value>,
        auth: Auth,
    ) -> WireResponse {
        self.request(method, path, auth, body).await
    }

    async fn request(
        &self,
        method: Method,
        path: &str,
        auth: Auth,
        body: Option<Value>,
    ) -> WireResponse {
        let mut request = self
            .client
            .request(method, format!("{}{}", self.base_url, path));
        request = match auth {
            Auth::None => request,
            Auth::GlobalAdmin => request.header(
                COOKIE,
                format!("{SESSION_COOKIE}={}", self.global_admin_token),
            ),
            Auth::Admin => request.header(COOKIE, format!("{SESSION_COOKIE}={}", self.admin_token)),
            Auth::User => request.header(COOKIE, format!("{SESSION_COOKIE}={}", self.user_token)),
        };
        if let Some(body) = body {
            request = request.json(&body);
        }
        let response = request
            .send()
            .await
            .unwrap_or_else(|error| panic!("request {path}: {error}"));
        let status = response.status();
        let headers = response.headers().clone();
        let body = response
            .bytes()
            .await
            .unwrap_or_else(|error| panic!("read {path}: {error}"))
            .to_vec();
        WireResponse {
            status,
            headers,
            body,
        }
    }

    pub fn client_config(&self, auth: Auth, codec: CodecFormat) -> ClientConfig {
        let mut config = ClientConfig::new(self.base_url.parse().expect("Connect base URI"))
            .with_codec_format(codec)
            .with_default_timeout(Duration::from_secs(30));
        config =
            match auth {
                Auth::None => config,
                Auth::GlobalAdmin => config.with_default_header(
                    COOKIE,
                    format!("{SESSION_COOKIE}={}", self.global_admin_token),
                ),
                Auth::Admin => config
                    .with_default_header(COOKIE, format!("{SESSION_COOKIE}={}", self.admin_token)),
                Auth::User => config
                    .with_default_header(COOKIE, format!("{SESSION_COOKIE}={}", self.user_token)),
            };
        config
    }
}

fn required_env(name: &str) -> String {
    env::var(name).unwrap_or_else(|_| panic!("{name} is required by the selected contract"))
}

pub(super) fn object<'a>(value: &'a Value, label: &str) -> &'a Map<String, Value> {
    value
        .as_object()
        .unwrap_or_else(|| panic!("{label}: expected object, got {value}"))
}

pub(super) fn array<'a>(value: &'a Value, label: &str) -> &'a Vec<Value> {
    value
        .as_array()
        .unwrap_or_else(|| panic!("{label}: expected array, got {value}"))
}

pub(super) fn assert_connect_error(
    response: &WireResponse,
    status: StatusCode,
    code: &str,
    message: &str,
) -> Value {
    response.assert_status(status, "Connect error");
    let body = response.json();
    assert_eq!(body["code"], code, "Connect error body={body}");
    if !message.is_empty() {
        assert_eq!(body["message"], message, "Connect error body={body}");
    }
    body
}

pub(super) fn assert_rpc_error(error: &ConnectError, code: ErrorCode, message: &str) {
    assert_eq!(error.code, code, "RPC error: {error:?}");
    if !message.is_empty() {
        assert!(
            error
                .message
                .as_deref()
                .is_some_and(|actual| actual.contains(message)),
            "RPC error message {:?} lacks {message:?}",
            error.message
        );
    }
}

pub(super) fn rpc_has_retry_info(error: &ConnectError) -> bool {
    error.details.iter().any(|detail| {
        (detail.type_url == "google.rpc.RetryInfo"
            || detail.type_url.rsplit('/').next() == Some("google.rpc.RetryInfo"))
            && decode_rpc_detail::<RetryInfo>(detail).is_some()
    })
}

pub(super) fn assert_rpc_bad_request(error: &ConnectError, fields: &[&str]) {
    let bad_request = error
        .details
        .iter()
        .find_map(|detail| {
            (detail.type_url == "google.rpc.BadRequest"
                || detail.type_url.rsplit('/').next() == Some("google.rpc.BadRequest"))
            .then(|| decode_rpc_detail::<BadRequest>(detail))
            .flatten()
        })
        .expect("RPC error lacks google.rpc.BadRequest");
    let actual: Vec<_> = bad_request
        .field_violations
        .iter()
        .map(|violation| {
            assert!(!violation.description.is_empty());
            violation.field.as_str()
        })
        .collect();
    assert_eq!(actual, fields);
}

fn decode_rpc_detail<M: buffa::Message>(detail: &connectrpc::ErrorDetail) -> Option<M> {
    let encoded = detail.value.as_deref()?;
    let bytes = base64::engine::general_purpose::STANDARD_NO_PAD
        .decode(encoded)
        .or_else(|_| base64::engine::general_purpose::STANDARD.decode(encoded))
        .ok()?;
    M::decode_from_slice(&bytes).ok()
}

fn detail_bytes(body: &Value, wanted: &str) -> Vec<u8> {
    let details = array(&body["details"], "Connect error details");
    for detail in details {
        let fields = object(detail, "Connect error detail");
        assert_eq!(
            fields.len(),
            2,
            "detail must contain exactly type and value: {detail}"
        );
        if fields["type"] != wanted {
            continue;
        }
        let encoded = fields["value"]
            .as_str()
            .expect("Connect detail value string");
        for engine in [
            &base64::engine::general_purpose::STANDARD,
            &base64::engine::general_purpose::STANDARD_NO_PAD,
        ] {
            if let Ok(bytes) = engine.decode(encoded) {
                return bytes;
            }
        }
        panic!("{wanted} detail is not standard base64");
    }
    panic!("Connect error lacks {wanted} detail: {body}");
}

pub(super) fn assert_bad_request(body: &Value, fields: &[&str]) {
    let detail = BadRequest::decode_from_slice(&detail_bytes(body, "google.rpc.BadRequest"))
        .expect("decode google.rpc.BadRequest");
    let actual: Vec<_> = detail
        .field_violations
        .iter()
        .map(|violation| {
            assert!(
                !violation.description.is_empty(),
                "BadRequest field {} lacks a description",
                violation.field
            );
            violation.field.as_str()
        })
        .collect();
    assert_eq!(actual, fields);
}

pub(super) fn assert_error_info(response: &WireResponse, body: &Value, reason: &str) {
    let detail = ErrorInfo::decode_from_slice(&detail_bytes(body, "google.rpc.ErrorInfo"))
        .expect("decode google.rpc.ErrorInfo");
    assert_eq!(detail.reason, reason);
    assert_eq!(detail.domain, "codewire.sh");
    let request_id = response
        .headers
        .get("x-request-id")
        .and_then(|value| value.to_str().ok())
        .expect("x-request-id response header");
    assert_eq!(
        detail.metadata.get("request_id").map(String::as_str),
        Some(request_id)
    );
}

pub(super) fn assert_retry_info(body: &Value) {
    let detail = RetryInfo::decode_from_slice(&detail_bytes(body, "google.rpc.RetryInfo"))
        .expect("decode google.rpc.RetryInfo");
    let delay = detail
        .retry_delay
        .as_option()
        .expect("RetryInfo retry_delay");
    assert_eq!(delay.seconds, 1);
    assert_eq!(delay.nanos, 0);
}

pub(super) fn has_detail(body: &Value, wanted: &str) -> bool {
    body["details"]
        .as_array()
        .is_some_and(|details| details.iter().any(|detail| detail["type"] == wanted))
}
