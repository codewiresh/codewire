//! A unary call whose bearer the auth layer refused is sent once more with
//! the provider's renewed token, and nothing else is ever sent twice
//! (docs/dev/AUTH-POLICY.md, "Native sign-in lifetimes").

use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};

use async_trait::async_trait;
use buffa::Message as _;
use codewire_proto::codewire::v1::{ApiKey, ListApiKeysRequest, ListApiKeysResponse};
use codewire_proto::google::rpc::ErrorInfo;
use wiremock::matchers::{header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use super::*;
use crate::{CodewireClient, StaticTokenProvider};

const LIST_API_KEYS_PATH: &str = "/codewire.v1.ApiKeyService/ListApiKeys";

/// A sign-in that renews to `new-token` when asked after a refusal.
#[derive(Default)]
struct Renewing {
    token: Mutex<Option<String>>,
    renewals: AtomicUsize,
}

#[async_trait]
impl TokenProvider for Renewing {
    async fn token(&self) -> Result<BearerToken, ClientError> {
        let token = self.token.lock().unwrap().clone();
        BearerToken::new(token.unwrap_or_else(|| "old-token".to_owned()))
    }

    async fn after_refusal(
        &self,
        rejected: &BearerToken,
    ) -> Result<Option<BearerToken>, ClientError> {
        assert_eq!(rejected.expose_secret(), "old-token");
        self.renewals.fetch_add(1, Ordering::SeqCst);
        *self.token.lock().unwrap() = Some("new-token".to_owned());
        BearerToken::new("new-token").map(Some)
    }
}

fn client(server: &MockServer, tokens: Arc<dyn TokenProvider>) -> CodewireClient {
    CodewireClient::with_http_token_provider(
        ClientConfig::new(server.uri()).expect("server URL"),
        tokens,
        reqwest::Client::new(),
    )
    .expect("client")
}

/// An `Unauthenticated` answer, with the auth layer's reason when `reason`.
fn refusal(reason: Option<&str>) -> ResponseTemplate {
    let mut error = ConnectError::unauthenticated("session expired");
    if let Some(reason) = reason {
        error = error.with_detail(connectrpc::ErrorDetail::from_message(
            "google.rpc.ErrorInfo",
            &ErrorInfo {
                reason: reason.into(),
                domain: BEARER_REFUSED_DOMAIN.into(),
                ..Default::default()
            },
        ));
    }
    ResponseTemplate::new(401)
        .insert_header("content-type", "application/json")
        .set_body_bytes(error.to_json().to_vec())
}

fn listed() -> ResponseTemplate {
    let response = ListApiKeysResponse {
        api_keys: vec![ApiKey {
            id: "key_123".into(),
            ..Default::default()
        }],
        ..Default::default()
    };
    ResponseTemplate::new(200)
        .insert_header("content-type", "application/proto")
        .set_body_bytes(response.encode_to_vec())
}

async fn answer(server: &MockServer, token: &str, response: ResponseTemplate, times: u64) {
    Mock::given(method("POST"))
        .and(path(LIST_API_KEYS_PATH))
        .and(header("authorization", format!("Bearer {token}")))
        .respond_with(response)
        .expect(times)
        .mount(server)
        .await;
}

async fn list(client: &CodewireClient) -> Result<ListApiKeysResponse, ClientError> {
    client
        .list_api_keys(ListApiKeysRequest {
            org_id: "org_123".into(),
            ..Default::default()
        })
        .await
}

#[tokio::test]
async fn a_refused_bearer_is_renewed_and_the_call_sent_once_more() {
    let server = MockServer::start().await;
    answer(&server, "old-token", refusal(Some(BEARER_REFUSED)), 1).await;
    answer(&server, "new-token", listed(), 1).await;
    let tokens = Arc::new(Renewing::default());
    let response = list(&client(&server, tokens.clone()))
        .await
        .expect("listed");
    assert_eq!(response.api_keys[0].id, "key_123");
    assert_eq!(tokens.renewals.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn a_second_refusal_ends_the_call() {
    let server = MockServer::start().await;
    answer(&server, "old-token", refusal(Some(BEARER_REFUSED)), 1).await;
    answer(&server, "new-token", refusal(Some(BEARER_REFUSED)), 1).await;
    let tokens = Arc::new(Renewing::default());
    let error = list(&client(&server, tokens.clone())).await.unwrap_err();
    assert_eq!(error.code(), ErrorCode::Unauthenticated);
    assert_eq!(tokens.renewals.load(Ordering::SeqCst), 1);
}

/// A handler's `Unauthenticated` may follow a change, so it is never sent
/// again, and the sign-in is not renewed for it.
#[tokio::test]
async fn an_unauthenticated_answer_without_the_reason_is_not_sent_again() {
    let server = MockServer::start().await;
    answer(&server, "old-token", refusal(None), 1).await;
    answer(&server, "old-token", refusal(Some("SESSION_EXPIRED")), 0).await;
    let tokens = Arc::new(Renewing::default());
    let error = list(&client(&server, tokens.clone())).await.unwrap_err();
    assert_eq!(error.code(), ErrorCode::Unauthenticated);
    assert_eq!(tokens.renewals.load(Ordering::SeqCst), 0);
}

/// An API key or user token has no renewal: its refusal is the answer, after
/// one request.
#[tokio::test]
async fn a_refused_api_key_is_sent_once() {
    let server = MockServer::start().await;
    answer(&server, "cw_key", refusal(Some(BEARER_REFUSED)), 1).await;
    let tokens = Arc::new(StaticTokenProvider::new("cw_key").expect("key"));
    let error = list(&client(&server, tokens)).await.unwrap_err();
    assert_eq!(error.code(), ErrorCode::Unauthenticated);
    assert_eq!(error.reason(), Some(BEARER_REFUSED));
}

#[test]
fn only_connect_unary_content_is_sent_again() {
    let typed = |value: &str| {
        let mut headers = HeaderMap::new();
        headers.insert(
            http::header::CONTENT_TYPE,
            HeaderValue::from_str(value).unwrap(),
        );
        unary(&headers)
    };
    assert!(typed("application/proto"));
    assert!(typed("application/json; charset=utf-8"));
    assert!(!typed("application/connect+proto"));
    assert!(!typed("application/grpc"));
    assert!(!unary(&HeaderMap::new()));
}
