//! Revoking a deleted credential's token at its provider (#4717 C6), against
//! the scripted provider: the exact request each revocation sends, and how
//! each answer is reported. Only the provider's own success status is
//! `Confirmed`; a redirect is an answer, never followed.

use std::sync::Arc;

use base64::Engine as _;
use http::{Method, StatusCode, header};
use serde_json::json;

use super::test_support::ScriptedProvider;
use super::{ProviderRevocation, RevocationFailure, codex, github};
use crate::BrokerUpstreamTransport;

const REFRESH_TOKEN: &str = "synthetic-refresh-token";
const ACCESS_TOKEN: &str = "synthetic-access-token";
const CLIENT_ID: &str = "Iv1.syntheticclient";
const CLIENT_SECRET: &str = "synthetic-client-secret";

fn upstream(provider: &Arc<ScriptedProvider>) -> Arc<dyn BrokerUpstreamTransport> {
    provider.clone()
}

#[tokio::test]
async fn codex_revocation_posts_the_refresh_token_as_the_public_client() {
    let provider = Arc::new(ScriptedProvider::default());
    provider.answer(StatusCode::OK, json!({}));
    assert_eq!(
        codex::revoke_refresh_token(&upstream(&provider), REFRESH_TOKEN).await,
        ProviderRevocation::Confirmed
    );
    let sent = provider.sent();
    assert_eq!(sent.len(), 1);
    assert_eq!(sent[0].method, Method::POST);
    assert_eq!(
        sent[0].target,
        "https://auth.openai.com/api/accounts/oauth/revoke"
    );
    assert_eq!(
        sent[0].headers[header::CONTENT_TYPE],
        "application/x-www-form-urlencoded"
    );
    assert_eq!(
        sent[0].form(),
        [
            ("token".to_owned(), REFRESH_TOKEN.to_owned()),
            ("token_type_hint".to_owned(), "refresh_token".to_owned()),
            (
                "client_id".to_owned(),
                super::CODEX_OAUTH_CLIENT_ID.to_owned()
            ),
        ]
    );
    assert!(
        sent[0].headers.get(header::AUTHORIZATION).is_none(),
        "a public client sends no secret"
    );
}

#[tokio::test]
async fn codex_revocation_is_confirmed_only_by_200() {
    for (status, expected) in [
        (StatusCode::BAD_REQUEST, RevocationFailure::Refused(400)),
        (StatusCode::UNAUTHORIZED, RevocationFailure::Refused(401)),
        (StatusCode::FOUND, RevocationFailure::Refused(302)),
        (
            StatusCode::TOO_MANY_REQUESTS,
            RevocationFailure::Unavailable,
        ),
        (
            StatusCode::SERVICE_UNAVAILABLE,
            RevocationFailure::Unavailable,
        ),
    ] {
        let provider = Arc::new(ScriptedProvider::default());
        provider.answer(status, json!({ "error": "synthetic" }));
        assert_eq!(
            codex::revoke_refresh_token(&upstream(&provider), REFRESH_TOKEN).await,
            ProviderRevocation::Failed(expected),
            "{status}"
        );
        assert_eq!(provider.sent().len(), 1, "{status}: one request, no retry");
    }
    // No answer at all: the transport failed.
    let provider = Arc::new(ScriptedProvider::default());
    assert_eq!(
        codex::revoke_refresh_token(&upstream(&provider), REFRESH_TOKEN).await,
        ProviderRevocation::Failed(RevocationFailure::Unavailable)
    );
}

#[tokio::test]
async fn github_revocation_deletes_the_user_token_with_the_app_secret() {
    let provider = Arc::new(ScriptedProvider::default());
    provider.answer_bytes(StatusCode::NO_CONTENT, Vec::new());
    assert_eq!(
        github::revoke_app_token(&upstream(&provider), CLIENT_ID, CLIENT_SECRET, ACCESS_TOKEN)
            .await,
        ProviderRevocation::Confirmed
    );
    let sent = provider.sent();
    assert_eq!(sent.len(), 1);
    assert_eq!(sent[0].method, Method::DELETE);
    assert_eq!(
        sent[0].target,
        format!("https://api.github.com/applications/{CLIENT_ID}/token")
    );
    assert_eq!(sent[0].json(), json!({ "access_token": ACCESS_TOKEN }));
    let authorization = &sent[0].headers[header::AUTHORIZATION];
    assert_eq!(
        authorization,
        format!(
            "Basic {}",
            base64::engine::general_purpose::STANDARD
                .encode(format!("{CLIENT_ID}:{CLIENT_SECRET}"))
        )
        .as_str()
    );
    assert!(authorization.is_sensitive());
    assert_eq!(sent[0].headers[header::USER_AGENT], "Codewire");
    assert_eq!(sent[0].headers["x-github-api-version"], "2022-11-28");
    assert_eq!(
        sent[0].headers[header::ACCEPT],
        "application/vnd.github+json"
    );
}

#[tokio::test]
async fn github_revocation_is_confirmed_only_by_204() {
    for (status, expected) in [
        (StatusCode::OK, RevocationFailure::Refused(200)),
        (StatusCode::NOT_FOUND, RevocationFailure::Refused(404)),
        (
            StatusCode::UNPROCESSABLE_ENTITY,
            RevocationFailure::Refused(422),
        ),
        (StatusCode::FOUND, RevocationFailure::Refused(302)),
        (StatusCode::BAD_GATEWAY, RevocationFailure::Unavailable),
    ] {
        let provider = Arc::new(ScriptedProvider::default());
        provider.answer(status, json!({ "message": "synthetic" }));
        assert_eq!(
            github::revoke_app_token(&upstream(&provider), CLIENT_ID, CLIENT_SECRET, ACCESS_TOKEN)
                .await,
            ProviderRevocation::Failed(expected),
            "{status}"
        );
        assert_eq!(provider.sent().len(), 1, "{status}: one request, no retry");
    }
}

#[test]
fn a_failure_names_its_class_and_status_only() {
    assert_eq!(
        RevocationFailure::Unavailable.to_string(),
        "the provider could not be reached"
    );
    assert_eq!(
        RevocationFailure::Refused(400).to_string(),
        "the provider refused it (HTTP 400)"
    );
}

fn jwt(payload: serde_json::Value) -> String {
    let encode = |bytes: &[u8]| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes);
    format!(
        "{}.{}.synthetic-signature",
        encode(br#"{"alg":"none"}"#),
        encode(&serde_json::to_vec(&payload).unwrap())
    )
}

#[tokio::test]
async fn a_stored_codex_bundle_revokes_its_own_refresh_token() {
    let (bundle, _) = crate::codex_oauth::import_codex_tokens(
        zeroize::Zeroizing::new(jwt(json!({
            "email": "developer@example.test",
            "https://api.openai.com/auth": { "chatgpt_account_id": "synthetic-account" }
        }))),
        zeroize::Zeroizing::new(jwt(json!({ "exp": 4_000_000_000_u64 }))),
        zeroize::Zeroizing::new(REFRESH_TOKEN.to_owned()),
    )
    .unwrap()
    .into_parts();
    let provider = Arc::new(ScriptedProvider::default());
    provider.answer(StatusCode::OK, json!({}));
    assert_eq!(
        codex::revoke_stored(&upstream(&provider), bundle.as_bytes()).await,
        ProviderRevocation::Confirmed
    );
    let sent = provider.sent();
    assert_eq!(sent.len(), 1);
    assert!(
        sent[0]
            .form()
            .contains(&("token".to_owned(), REFRESH_TOKEN.to_owned()))
    );
}

#[tokio::test]
async fn unreadable_stored_material_asks_the_provider_nothing() {
    let provider = Arc::new(ScriptedProvider::default());
    assert_eq!(
        codex::revoke_stored(&upstream(&provider), b"not a codex bundle").await,
        ProviderRevocation::Failed(RevocationFailure::Unreadable)
    );
    assert!(provider.sent().is_empty());
}

/// A provider that accepts the request and never answers.
struct Silent;

#[async_trait::async_trait]
impl BrokerUpstreamTransport for Silent {
    async fn execute(
        &self,
        _request: crate::BrokerUpstreamRequest,
    ) -> Result<crate::BrokerUpstreamResponse, crate::BrokerUpstreamError> {
        std::future::pending().await
    }
}

#[tokio::test(start_paused = true)]
async fn a_provider_that_never_answers_is_unavailable_after_eight_seconds() {
    let silent: Arc<dyn BrokerUpstreamTransport> = Arc::new(Silent);
    let started = tokio::time::Instant::now();
    assert_eq!(
        codex::revoke_refresh_token(&silent, REFRESH_TOKEN).await,
        ProviderRevocation::Failed(RevocationFailure::Unavailable)
    );
    assert_eq!(started.elapsed(), std::time::Duration::from_secs(8));
    let started = tokio::time::Instant::now();
    assert_eq!(
        github::revoke_app_token(&silent, CLIENT_ID, CLIENT_SECRET, ACCESS_TOKEN).await,
        ProviderRevocation::Failed(RevocationFailure::Unavailable)
    );
    assert_eq!(started.elapsed(), std::time::Duration::from_secs(8));
}
