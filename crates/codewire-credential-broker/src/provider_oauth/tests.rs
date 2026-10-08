//! Contract tests against a scripted synthetic provider. Time is paused, so
//! poll intervals and code lifetimes are exact and instant.

use std::sync::Arc;
use std::time::Duration;

use base64::Engine as _;
use http::{Method, StatusCode};
use serde_json::json;

use super::codex::CodexDeviceLogin;
use super::github::{GitHubDeviceLogin, GitHubDeviceLoginConfig};
use super::test_support::ScriptedProvider;
use super::*;
use crate::codex_oauth::CodexOAuthCredential;

const USERCODE_URL: &str = "https://auth.openai.com/api/accounts/deviceauth/usercode";
const DEVICE_TOKEN_URL: &str = "https://auth.openai.com/api/accounts/deviceauth/token";
const GITHUB_DEVICE_CODE_URL: &str = "https://github.com/login/device/code";
const GITHUB_TOKEN_URL: &str = "https://github.com/login/oauth/access_token";
const DEVICE_AUTH_ID: &str = "synthetic-device-auth-id";
const GITHUB_DEVICE_CODE: &str = "synthetic-github-device-code";
const GITHUB_USER_TOKEN: &str = "ghu_synthetic_device_user_token";

/// The imports deliberately have no `Debug`, so `unwrap_err` is unavailable.
fn failure<T>(result: Result<T, DeviceLoginError>) -> DeviceLoginError {
    match result {
        Ok(_) => panic!("the device login unexpectedly succeeded"),
        Err(error) => error,
    }
}

fn jwt(payload: serde_json::Value) -> String {
    let encode = |bytes: &[u8]| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes);
    format!(
        "{}.{}.synthetic-signature",
        encode(br#"{"alg":"none"}"#),
        encode(&serde_json::to_vec(&payload).unwrap())
    )
}

fn codex_tokens(account_id: Option<&str>) -> serde_json::Value {
    let auth = account_id.map_or_else(
        || json!({}),
        |account| json!({"chatgpt_account_id": account}),
    );
    json!({
        "id_token": jwt(json!({
            "email": "developer@example.test",
            "https://api.openai.com/auth": auth
        })),
        "access_token": jwt(json!({"exp": 4_000_000_000_u64})),
        "refresh_token": "synthetic-refresh-token",
    })
}

fn codex_usercode() -> serde_json::Value {
    json!({"device_auth_id": DEVICE_AUTH_ID, "usercode": "ABCD-1234", "interval": "5"})
}

fn codex(provider: &Arc<ScriptedProvider>) -> CodexDeviceLogin {
    CodexDeviceLogin::new(provider.clone())
}

#[tokio::test(start_paused = true)]
async fn codex_device_login_polls_until_approval_and_imports_the_issued_tokens() {
    let provider = Arc::new(ScriptedProvider::default());
    provider
        .answer(StatusCode::OK, codex_usercode())
        .answer(StatusCode::FORBIDDEN, json!({}))
        .answer(StatusCode::NOT_FOUND, json!({}))
        .answer(
            StatusCode::OK,
            json!({
                "authorization_code": "synthetic-authorization-code",
                "code_challenge": "synthetic-challenge",
                "code_verifier": "synthetic-verifier",
            }),
        )
        .answer(StatusCode::OK, codex_tokens(Some("account-work")));
    let login = codex(&provider);
    let pending = login.start().await.unwrap();
    assert_eq!(
        pending.challenge().verification_url(),
        "https://auth.openai.com/codex/device"
    );
    assert_eq!(pending.challenge().user_code(), "ABCD-1234");
    let import = login.complete(pending).await.unwrap();
    assert_eq!(import.account_hint(), Some("developer@example.test"));
    let (bundle, _) = import.into_parts();
    let credential = CodexOAuthCredential::parse(bundle.as_bytes()).unwrap();
    assert_eq!(credential.account_id(), "account-work");
    assert_eq!(credential.refresh_token(), "synthetic-refresh-token");

    let sent = provider.sent();
    let targets: Vec<_> = sent
        .iter()
        .map(|sent| (sent.method.clone(), sent.target.as_str()))
        .collect();
    assert_eq!(
        targets,
        [
            (Method::POST, USERCODE_URL),
            (Method::POST, DEVICE_TOKEN_URL),
            (Method::POST, DEVICE_TOKEN_URL),
            (Method::POST, DEVICE_TOKEN_URL),
            (Method::POST, "https://auth.openai.com/oauth/token"),
        ]
    );
    assert!(sent[..4].iter().all(|sent| {
        sent.headers
            .get(http::header::CONTENT_TYPE)
            .map(|value| value.as_bytes())
            == Some(b"application/json".as_slice())
    }));
    assert_eq!(
        sent[0].json(),
        json!({"client_id": "app_EMoamEEZ73f0CkXaXp7hrann"})
    );
    assert_eq!(
        sent[1].json(),
        json!({"device_auth_id": DEVICE_AUTH_ID, "user_code": "ABCD-1234"})
    );
    for pair in sent[..4].windows(2) {
        assert_eq!(pair[1].at - pair[0].at, Duration::from_secs(5));
    }
    assert_eq!(
        sent[4].form(),
        [
            ("grant_type", "authorization_code"),
            ("code", "synthetic-authorization-code"),
            (
                "redirect_uri",
                "https://auth.openai.com/deviceauth/callback"
            ),
            ("client_id", "app_EMoamEEZ73f0CkXaXp7hrann"),
            ("code_verifier", "synthetic-verifier"),
        ]
        .map(|(key, value)| (key.to_owned(), value.to_owned()))
    );
}

#[tokio::test(start_paused = true)]
async fn codex_device_login_reports_disabled_expired_denied_and_invalid_outcomes() {
    let provider = Arc::new(ScriptedProvider::default());
    provider.answer(StatusCode::NOT_FOUND, json!({}));
    assert_eq!(
        codex(&provider).start().await.unwrap_err(),
        DeviceLoginError::DeviceLoginDisabled
    );

    // A code that is never approved ends at its fifteen-minute lifetime.
    let provider = Arc::new(ScriptedProvider::default());
    provider.answer(StatusCode::OK, codex_usercode());
    provider.then_always(StatusCode::FORBIDDEN, json!({}));
    let login = codex(&provider);
    let pending = login.start().await.unwrap();
    let started = tokio::time::Instant::now();
    assert_eq!(
        failure(login.complete(pending).await),
        DeviceLoginError::Expired
    );
    assert!(started.elapsed() < Duration::from_secs(15 * 60));
    assert_eq!(provider.sent().len(), 1 + (15 * 60 / 5 - 1));

    let approved = json!({
        "authorization_code": "synthetic-authorization-code",
        "code_challenge": "synthetic-challenge",
        "code_verifier": "synthetic-verifier",
    });
    for (exchange_status, exchange_body, expected) in [
        (
            StatusCode::BAD_REQUEST,
            json!({"error": "invalid_grant"}),
            DeviceLoginError::AccessDenied,
        ),
        (
            StatusCode::BAD_GATEWAY,
            json!({}),
            DeviceLoginError::Unavailable,
        ),
        // Without a ChatGPT account claim there is no identity to bind.
        (
            StatusCode::OK,
            codex_tokens(None),
            DeviceLoginError::InvalidResponse,
        ),
    ] {
        let provider = Arc::new(ScriptedProvider::default());
        provider
            .answer(StatusCode::OK, codex_usercode())
            .answer(StatusCode::OK, approved.clone())
            .answer(exchange_status, exchange_body);
        let login = codex(&provider);
        let pending = login.start().await.unwrap();
        assert_eq!(failure(login.complete(pending).await), expected);
    }
}

#[tokio::test(start_paused = true)]
async fn device_login_rejects_oversized_and_malformed_answers() {
    let provider = Arc::new(ScriptedProvider::default());
    provider.answer_bytes(StatusCode::OK, vec![b' '; 64 * 1024 + 1]);
    assert_eq!(
        codex(&provider).start().await.unwrap_err(),
        DeviceLoginError::InvalidResponse
    );
    for usercode in [
        json!({"device_auth_id": DEVICE_AUTH_ID, "usercode": "ABCD 1234", "interval": "5"}),
        json!({"device_auth_id": DEVICE_AUTH_ID, "usercode": "", "interval": "5"}),
        json!({"device_auth_id": "", "usercode": "ABCD-1234", "interval": "5"}),
        json!({"device_auth_id": DEVICE_AUTH_ID, "usercode": "ABCD-1234", "interval": "soon"}),
        json!({"usercode": "ABCD-1234"}),
    ] {
        let provider = Arc::new(ScriptedProvider::default());
        provider.answer(StatusCode::OK, usercode);
        assert_eq!(
            codex(&provider).start().await.unwrap_err(),
            DeviceLoginError::InvalidResponse
        );
    }
}

#[tokio::test(start_paused = true)]
async fn pending_logins_and_challenges_never_format_provider_handles() {
    let provider = Arc::new(ScriptedProvider::default());
    provider.answer(StatusCode::OK, codex_usercode());
    let pending = codex(&provider).start().await.unwrap();
    let formatted = format!("{pending:?} {:?}", pending.challenge());
    assert!(!formatted.contains(DEVICE_AUTH_ID), "{formatted}");
    assert!(!formatted.contains("ABCD-1234"), "{formatted}");
    let secret = Secret::new("synthetic-secret-value".to_owned());
    assert_eq!(format!("{secret:?} {secret}"), "[REDACTED] [REDACTED]");

    let provider = Arc::new(ScriptedProvider::default());
    provider.answer(StatusCode::OK, github_device_code(json!(5)));
    let pending = github(&provider).start().await.unwrap();
    let formatted = format!("{pending:?}");
    assert!(!formatted.contains(GITHUB_DEVICE_CODE), "{formatted}");
    assert!(!formatted.contains("WDJB-MJHT"), "{formatted}");
}

fn github(provider: &Arc<ScriptedProvider>) -> GitHubDeviceLogin {
    GitHubDeviceLogin::new(
        GitHubDeviceLoginConfig::new("Iv1.synthetic-client".to_owned(), "codewire".to_owned())
            .unwrap(),
        provider.clone(),
    )
}

fn github_device_code(interval: serde_json::Value) -> serde_json::Value {
    json!({
        "device_code": GITHUB_DEVICE_CODE,
        "user_code": "WDJB-MJHT",
        "verification_uri": "https://github.com/login/device",
        "expires_in": 900,
        "interval": interval,
    })
}

fn github_identity(provider: &ScriptedProvider, installations: serde_json::Value) {
    provider
        .answer(StatusCode::OK, json!({"id": 73, "login": "octo-user"}))
        .answer(StatusCode::OK, json!({"installations": installations}));
}

#[tokio::test(start_paused = true)]
async fn github_device_login_honors_slow_down_and_runs_the_dashboard_identity_checks() {
    let provider = Arc::new(ScriptedProvider::default());
    provider
        .answer(StatusCode::OK, github_device_code(json!(5)))
        .answer(StatusCode::OK, json!({"error": "authorization_pending"}))
        .answer(
            StatusCode::OK,
            json!({"error": "slow_down", "interval": 10, "error_description": "too fast"}),
        )
        .answer(StatusCode::OK, json!({"error": "slow_down"}))
        .answer(
            StatusCode::OK,
            json!({"access_token": GITHUB_USER_TOKEN, "token_type": "bearer", "scope": ""}),
        );
    github_identity(&provider, json!([{"id": 41, "app_slug": "codewire"}]));
    let login = github(&provider);
    let pending = login.start().await.unwrap();
    assert_eq!(
        pending.challenge().verification_url(),
        "https://github.com/login/device"
    );
    assert_eq!(pending.challenge().user_code(), "WDJB-MJHT");
    let mut import = login.complete(pending).await.unwrap();
    assert_eq!(import.account_hint(), "octo-user");
    let (material, account) = import.take_import().unwrap();
    assert_eq!(material.as_slice(), GITHUB_USER_TOKEN.as_bytes());
    assert_eq!(account.as_deref(), Some("octo-user"));

    let sent = provider.sent();
    let targets: Vec<_> = sent
        .iter()
        .map(|sent| (sent.method.clone(), sent.target.as_str()))
        .collect();
    assert_eq!(
        targets,
        [
            (Method::POST, GITHUB_DEVICE_CODE_URL),
            (Method::POST, GITHUB_TOKEN_URL),
            (Method::POST, GITHUB_TOKEN_URL),
            (Method::POST, GITHUB_TOKEN_URL),
            (Method::POST, GITHUB_TOKEN_URL),
            (Method::GET, "https://api.github.com/user"),
            (
                Method::GET,
                "https://api.github.com/user/installations?per_page=100&page=1"
            ),
        ]
    );
    assert_eq!(
        sent[0].form(),
        [("client_id".to_owned(), "Iv1.synthetic-client".to_owned())]
    );
    assert_eq!(
        sent[1].form(),
        [
            ("client_id", "Iv1.synthetic-client"),
            ("device_code", GITHUB_DEVICE_CODE),
            ("grant_type", "urn:ietf:params:oauth:grant-type:device_code"),
        ]
        .map(|(key, value)| (key.to_owned(), value.to_owned()))
    );
    assert!(sent[..5].iter().all(|sent| {
        sent.headers
            .get(http::header::ACCEPT)
            .map(|value| value.as_bytes())
            == Some(b"application/json".as_slice())
            && sent.headers.get(http::header::AUTHORIZATION).is_none()
    }));
    // No client secret is ever sent: a device login has none.
    assert!(
        sent[..5]
            .iter()
            .all(|sent| { sent.form().iter().all(|(key, _)| key != "client_secret") })
    );
    // 5 s, then 5 s, then the provider's 10 s, then 10 s + 5 s.
    let gaps: Vec<_> = sent[..5]
        .windows(2)
        .map(|pair| (pair[1].at - pair[0].at).as_secs())
        .collect();
    assert_eq!(gaps, [5, 5, 10, 15]);
}

#[tokio::test(start_paused = true)]
async fn github_device_login_never_polls_faster_than_the_current_interval() {
    let provider = Arc::new(ScriptedProvider::default());
    provider
        .answer(StatusCode::OK, github_device_code(json!(7)))
        .answer(StatusCode::OK, json!({"error": "slow_down", "interval": 3}))
        .answer(
            StatusCode::OK,
            json!({"access_token": GITHUB_USER_TOKEN, "token_type": "bearer"}),
        );
    github_identity(&provider, json!([{"id": 41, "app_slug": "codewire"}]));
    let login = github(&provider);
    let pending = login.start().await.unwrap();
    login.complete(pending).await.unwrap();
    let sent = provider.sent();
    assert_eq!((sent[2].at - sent[1].at).as_secs(), 7);
}

#[tokio::test(start_paused = true)]
async fn github_device_login_maps_provider_outcomes_and_bounds_the_flow_by_expires_in() {
    let provider = Arc::new(ScriptedProvider::default());
    provider.answer(StatusCode::OK, json!({"error": "device_flow_disabled"}));
    assert_eq!(
        github(&provider).start().await.unwrap_err(),
        DeviceLoginError::DeviceLoginDisabled
    );

    for (answer, expected) in [
        (json!({"error": "expired_token"}), DeviceLoginError::Expired),
        (
            json!({"error": "access_denied"}),
            DeviceLoginError::AccessDenied,
        ),
        (
            json!({"error": "incorrect_device_code"}),
            DeviceLoginError::InvalidResponse,
        ),
        (
            json!({"access_token": "gho_not_an_app_user_token", "token_type": "bearer"}),
            DeviceLoginError::InvalidResponse,
        ),
    ] {
        let provider = Arc::new(ScriptedProvider::default());
        provider
            .answer(StatusCode::OK, github_device_code(json!(5)))
            .answer(StatusCode::OK, answer);
        let login = github(&provider);
        let pending = login.start().await.unwrap();
        assert_eq!(failure(login.complete(pending).await), expected);
    }

    // An approved user without this App's installation gets no import.
    let provider = Arc::new(ScriptedProvider::default());
    provider
        .answer(StatusCode::OK, github_device_code(json!(5)))
        .answer(
            StatusCode::OK,
            json!({"access_token": GITHUB_USER_TOKEN, "token_type": "bearer"}),
        );
    github_identity(&provider, json!([{"id": 42, "app_slug": "another-app"}]));
    let login = github(&provider);
    let pending = login.start().await.unwrap();
    assert_eq!(
        failure(login.complete(pending).await),
        DeviceLoginError::InstallationRequired
    );

    // A code that is never approved ends within GitHub's expires_in.
    let provider = Arc::new(ScriptedProvider::default());
    provider.answer(StatusCode::OK, github_device_code(json!(5)));
    provider.then_always(StatusCode::OK, json!({"error": "authorization_pending"}));
    let login = github(&provider);
    let pending = login.start().await.unwrap();
    let started = tokio::time::Instant::now();
    assert_eq!(
        failure(login.complete(pending).await),
        DeviceLoginError::Expired
    );
    assert!(started.elapsed() < Duration::from_secs(900));
    assert_eq!(provider.sent().len(), 1 + (900 / 5 - 1));

    for expires_in in [0, 59, 3600] {
        let provider = Arc::new(ScriptedProvider::default());
        let mut answer = github_device_code(json!(5));
        answer["expires_in"] = json!(expires_in);
        provider.answer(StatusCode::OK, answer);
        assert_eq!(
            github(&provider).start().await.unwrap_err(),
            DeviceLoginError::InvalidResponse
        );
    }
}
