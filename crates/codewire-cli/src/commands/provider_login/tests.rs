//! The CLI's device logins against a scripted in-process provider. Real time:
//! each provider asks for the shortest poll interval, one second.

use std::collections::VecDeque;
use std::sync::Mutex;

use async_trait::async_trait;
use base64::Engine as _;
use codewire_credential_broker::{
    BrokerUpstreamError, BrokerUpstreamRequest, BrokerUpstreamResponse,
};
use http::{HeaderMap, HeaderValue, StatusCode, header};
use serde_json::{Value, json};

use super::*;

#[derive(Default)]
struct Scripted(Mutex<VecDeque<Value>>, Mutex<Vec<String>>);

#[async_trait]
impl BrokerUpstreamTransport for Scripted {
    async fn execute(
        &self,
        request: BrokerUpstreamRequest,
    ) -> Result<BrokerUpstreamResponse, BrokerUpstreamError> {
        let (_, target, _, _) = request.into_parts();
        self.1.lock().unwrap().push(target.as_str().to_owned());
        let Some(answer) = self.0.lock().unwrap().pop_front() else {
            // An unanswered provider never completes the login.
            return std::future::pending().await;
        };
        Ok(BrokerUpstreamResponse::new(
            StatusCode::OK,
            HeaderMap::from_iter([(
                header::CONTENT_TYPE,
                HeaderValue::from_static("application/json"),
            )]),
            Box::pin(futures::stream::once(async move {
                Ok(serde_json::to_vec(&answer).unwrap().into())
            })),
        ))
    }
}

fn scripted(answers: impl IntoIterator<Item = Value>) -> Arc<Scripted> {
    Arc::new(Scripted(
        Mutex::new(answers.into_iter().collect()),
        Mutex::default(),
    ))
}

#[tokio::test]
async fn codex_login_imports_the_issued_tokens_without_a_provider_cli() {
    let encode = |value: Value| {
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(serde_json::to_vec(&value).unwrap())
    };
    let provider = scripted([
        json!({"device_auth_id":"synthetic","user_code":"ABCD-EFGH","interval":"1"}),
        json!({"authorization_code":"code","code_challenge":"challenge","code_verifier":"verifier"}),
        json!({
            "id_token": format!("{}.{}.sig", encode(json!({})), encode(json!({
                "email":"person@example.test",
                "https://api.openai.com/auth":{"chatgpt_account_id":"account"}}))),
            "access_token":"synthetic-access","refresh_token":"synthetic-refresh"}),
    ]);
    let import = codex_device_login_with(provider.clone(), std::future::pending())
        .await
        .unwrap();
    assert_eq!(import.account_hint(), Some("person@example.test"));
    assert_eq!(
        provider.1.lock().unwrap().as_slice(),
        [
            "https://auth.openai.com/api/accounts/deviceauth/usercode",
            "https://auth.openai.com/api/accounts/deviceauth/token",
            "https://auth.openai.com/oauth/token",
        ]
    );
}

#[tokio::test]
async fn github_login_verifies_the_app_installation() {
    let provider = scripted([
        json!({"device_code":"synthetic","user_code":"ABCD-EFGH","expires_in":900,"interval":1}),
        json!({"access_token":"ghu_synthetic_user_token","token_type":"bearer"}),
        json!({"id":7,"login":"octo-user"}),
        json!({"installations":[{"id":41,"app_slug":"codewire-synthetic"}]}),
    ]);
    let app =
        GitHubDeviceLoginConfig::new("Iv1.synthetic".into(), "codewire-synthetic".into()).unwrap();
    let import = github_device_login_with(app, provider, std::future::pending())
        .await
        .unwrap();
    assert_eq!(import.account_hint(), "octo-user");
}

#[tokio::test]
async fn cancelling_a_pending_login_changes_nothing() {
    let provider = scripted([]);
    let error = match codex_device_login_with(provider, async {}).await {
        Ok(_) => panic!("a cancelled login must not complete"),
        Err(error) => error,
    };
    assert_eq!(error.to_string(), CANCELLED);
}
