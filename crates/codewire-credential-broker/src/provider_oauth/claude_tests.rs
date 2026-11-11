use std::sync::Arc;

use http::{Method, StatusCode, header};
use serde_json::json;

use super::*;
use crate::claude_oauth::ClaudeOAuthCredential;
use crate::provider_oauth::test_support::ScriptedProvider;

fn sign_in(provider: &Arc<ScriptedProvider>) -> ClaudeSignIn {
    ClaudeSignIn::new(provider.clone())
}

fn parts(handle: &str) -> (String, String, u64) {
    let parsed = parse_handle(handle).unwrap();
    (
        parsed.state.expose().to_owned(),
        parsed.verifier.expose().to_owned(),
        parsed.issued_at_unix,
    )
}

fn token_answer() -> serde_json::Value {
    json!({
        "token_type": "Bearer",
        "access_token": "synthetic-claude-access",
        "refresh_token": "synthetic-claude-refresh",
        "expires_in": 28_800,
        "scope": "user:profile user:inference user:sessions:claude_code user:mcp_servers user:file_upload user:plugins",
        "account": {"uuid": "synthetic-account", "email_address": "person@example.test"},
        "organization": {"uuid": "synthetic-organization", "name": "Synthetic"}
    })
}

fn profile_answer() -> serde_json::Value {
    json!({
        "account": {"uuid": "synthetic-account", "email": "person@example.test"},
        "organization": {
            "uuid": "synthetic-organization",
            "organization_type": "claude_max",
            "rate_limit_tier": "default_claude_max_20x"
        }
    })
}

#[test]
fn pkce_s256_matches_the_rfc7636_test_vector() {
    assert_eq!(
        s256_challenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"),
        "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
    );
    let first = random_text();
    assert!(random_text_shape(&first));
    assert_ne!(*first, *random_text());
}

#[test]
fn start_builds_claude_codes_claude_ai_authorize_request() {
    let started = start_at(1_800_000_000).unwrap();
    assert_eq!(started.expires_at_unix(), 1_800_000_000 + 15 * 60);
    let (state, verifier, issued) = parts(started.handle());
    assert_eq!(issued, 1_800_000_000);
    assert_ne!(state, verifier);
    let url = Url::parse(started.authorize_url()).unwrap();
    assert_eq!(url.scheme(), "https");
    assert_eq!(url.host_str(), Some("claude.com"));
    assert_eq!(url.path(), "/cai/oauth/authorize");
    let query: Vec<(String, String)> = url.query_pairs().into_owned().collect();
    assert_eq!(
        query,
        [
            ("code", "true"),
            ("client_id", "9d1c250a-e61b-44d9-88ed-5944d1962f5e"),
            ("response_type", "code"),
            (
                "redirect_uri",
                "https://platform.claude.com/oauth/code/callback"
            ),
            (
                "scope",
                "user:profile user:inference user:sessions:claude_code user:mcp_servers user:file_upload user:plugins"
            ),
            ("code_challenge", s256_challenge(&verifier).as_str()),
            ("code_challenge_method", "S256"),
            ("state", state.as_str()),
        ]
        .map(|(name, value)| (name.to_owned(), value.to_owned()))
    );
    assert!(!started.authorize_url().contains("org%3Acreate_api_key"));
    // Every start is new, and the handle never formats.
    let other = start_at(1_800_000_000).unwrap();
    assert_ne!(other.handle(), started.handle());
    assert!(!format!("{started:?}").contains(&verifier));
}

#[tokio::test]
async fn complete_exchanges_the_code_reads_the_plan_and_imports() {
    let provider = Arc::new(ScriptedProvider::default());
    provider
        .answer(StatusCode::OK, token_answer())
        .answer(StatusCode::OK, profile_answer());
    let started = sign_in(&provider).start().unwrap();
    let (state, verifier, _) = parts(started.handle());
    let imported = sign_in(&provider)
        .complete(started.handle(), &format!("  synthetic-code_1#{state}\n"))
        .await
        .unwrap();
    assert_eq!(imported.account_hint(), Some("person@example.test"));
    let (bundle, _) = imported.into_parts();
    let credential = ClaudeOAuthCredential::parse(bundle.as_bytes()).unwrap();
    assert_eq!(credential.access_token(), "synthetic-claude-access");
    assert_eq!(credential.refresh_token(), "synthetic-claude-refresh");
    assert_eq!(credential.scopes().len(), 6);
    assert_eq!(
        credential
            .subscription_type()
            .map(ClaudeSubscriptionType::as_str),
        Some("max")
    );
    assert_eq!(credential.rate_limit_tier(), Some("default_claude_max_20x"));

    let sent = provider.sent();
    assert_eq!(sent.len(), 2);
    assert_eq!(sent[0].method, Method::POST);
    assert_eq!(sent[0].target, "https://platform.claude.com/v1/oauth/token");
    assert_eq!(
        sent[0].headers[header::CONTENT_TYPE],
        HeaderValue::from_static("application/json")
    );
    assert_eq!(
        sent[0].json(),
        json!({
            "grant_type": "authorization_code",
            "code": "synthetic-code_1",
            "redirect_uri": "https://platform.claude.com/oauth/code/callback",
            "client_id": "9d1c250a-e61b-44d9-88ed-5944d1962f5e",
            "code_verifier": verifier,
            "state": state,
        })
    );
    assert_eq!(sent[1].method, Method::GET);
    assert_eq!(
        sent[1].target,
        "https://api.anthropic.com/api/oauth/profile"
    );
    assert_eq!(
        sent[1].headers[header::AUTHORIZATION],
        HeaderValue::from_static("Bearer synthetic-claude-access")
    );
    assert!(sent[1].headers[header::AUTHORIZATION].is_sensitive());
    assert!(sent[1].body.is_empty());
}

#[tokio::test]
async fn a_paste_from_another_sign_in_or_a_bad_handle_sends_nothing() {
    let provider = Arc::new(ScriptedProvider::default());
    let started = sign_in(&provider).start().unwrap();
    let (state, _, _) = parts(started.handle());
    let other = sign_in(&provider).start().unwrap();
    let (other_state, _, _) = parts(other.handle());
    for pasted in [
        format!("code#{other_state}"),
        "code".to_owned(),
        format!("#{state}"),
        format!("code with space#{state}"),
        format!("code#{state}x"),
        format!("{}#{state}", "c".repeat(MAX_CODE_BYTES + 1)),
    ] {
        assert_eq!(
            sign_in(&provider)
                .complete(started.handle(), &pasted)
                .await
                .err(),
            Some(ClaudeSignInError::InvalidCode),
            "{pasted}"
        );
    }
    for handle in [
        String::new(),
        "cwcs1.a.b.1".to_owned(),
        format!("cwcs2.{state}.{state}.1"),
        format!("cwcs1.{state}.{state}"),
        format!("cwcs1.{state}.{state}.1.extra"),
        format!("cwcs1.{state}.{state}.x"),
    ] {
        assert_eq!(
            sign_in(&provider)
                .complete(&handle, &format!("code#{state}"))
                .await
                .err(),
            Some(ClaudeSignInError::InvalidCode),
            "{handle}"
        );
    }
    assert!(provider.sent().is_empty());
}

#[tokio::test]
async fn an_old_sign_in_expires_before_anything_is_sent() {
    let provider = Arc::new(ScriptedProvider::default());
    let now = now_unix().unwrap();
    let old = start_at(now - CLAUDE_SIGN_IN_LIFETIME.as_secs()).unwrap();
    let (state, _, _) = parts(old.handle());
    assert_eq!(
        sign_in(&provider)
            .complete(old.handle(), &format!("code#{state}"))
            .await
            .err(),
        Some(ClaudeSignInError::Expired)
    );
    let future = start_at(now + 3_600).unwrap();
    let (state, _, _) = parts(future.handle());
    assert_eq!(
        sign_in(&provider)
            .complete(future.handle(), &format!("code#{state}"))
            .await
            .err(),
        Some(ClaudeSignInError::InvalidCode)
    );
    assert!(provider.sent().is_empty());
}

#[tokio::test]
async fn provider_refusals_and_outages_are_typed_without_provider_text() {
    for (status, body, expected) in [
        (
            StatusCode::BAD_REQUEST,
            json!({"error": "invalid_grant", "error_description": "secret detail"}),
            ClaudeSignInError::Denied,
        ),
        (
            StatusCode::UNAUTHORIZED,
            json!({}),
            ClaudeSignInError::Denied,
        ),
        (
            StatusCode::SERVICE_UNAVAILABLE,
            json!({}),
            ClaudeSignInError::Unavailable,
        ),
        (
            StatusCode::TOO_MANY_REQUESTS,
            json!({}),
            ClaudeSignInError::Unavailable,
        ),
        (
            StatusCode::FORBIDDEN,
            json!({}),
            ClaudeSignInError::InvalidResponse,
        ),
        (
            StatusCode::OK,
            json!({"access_token": "only"}),
            ClaudeSignInError::InvalidResponse,
        ),
    ] {
        let provider = Arc::new(ScriptedProvider::default());
        provider.answer(status, body);
        let started = sign_in(&provider).start().unwrap();
        let (state, _, _) = parts(started.handle());
        let error = sign_in(&provider)
            .complete(started.handle(), &format!("code#{state}"))
            .await
            .err()
            .unwrap();
        assert_eq!(error, expected, "{status}");
        assert!(!error.to_string().contains("secret"));
    }
    // A profile outage, a sign-in without the required scopes, or one that can
    // create API keys is no sign-in.
    for (token, profile_status) in [
        (token_answer(), StatusCode::INTERNAL_SERVER_ERROR),
        (
            json!({
                "access_token": "a",
                "refresh_token": "r",
                "expires_in": 28_800,
                "scope": "user:inference"
            }),
            StatusCode::OK,
        ),
        (
            json!({
                "access_token": "a",
                "refresh_token": "r",
                "expires_in": 28_800,
                "scope": "user:profile user:inference org:create_api_key"
            }),
            StatusCode::OK,
        ),
        (
            json!({
                "access_token": "a",
                "refresh_token": "r",
                "expires_in": 28_800,
                "scope": "user:profile org:create_api_key"
            }),
            StatusCode::OK,
        ),
    ] {
        let provider = Arc::new(ScriptedProvider::default());
        provider
            .answer(StatusCode::OK, token)
            .answer(profile_status, profile_answer());
        let started = sign_in(&provider).start().unwrap();
        let (state, _, _) = parts(started.handle());
        assert!(
            sign_in(&provider)
                .complete(started.handle(), &format!("code#{state}"))
                .await
                .is_err()
        );
    }
}

#[test]
fn refresh_requests_the_granted_scopes_and_keeps_an_absent_refresh_token() {
    let scopes = vec!["user:profile".to_owned(), "user:inference".to_owned()];
    let (target, body) = refresh_request("synthetic-refresh", &scopes).unwrap();
    assert_eq!(
        target.as_str(),
        "https://platform.claude.com/v1/oauth/token"
    );
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&body).unwrap(),
        json!({
            "grant_type": "refresh_token",
            "refresh_token": "synthetic-refresh",
            "client_id": "9d1c250a-e61b-44d9-88ed-5944d1962f5e",
            "scope": "user:profile user:inference",
        })
    );
    let rotated = parse_refresh_response(
        br#"{"access_token":"new-access","refresh_token":"new-refresh","expires_in":3600,"refresh_token_expires_in":86400,"scope":"user:profile user:inference"}"#,
    )
    .unwrap();
    assert_eq!(rotated.access_token.as_str(), "new-access");
    assert_eq!(
        rotated.refresh_token.as_deref().map(String::as_str),
        Some("new-refresh")
    );
    assert_eq!(rotated.expires_in, 3_600);
    assert_eq!(rotated.refresh_token_expires_in, Some(86_400));
    let kept =
        parse_refresh_response(br#"{"access_token":"new-access","expires_in":3600}"#).unwrap();
    assert!(kept.refresh_token.is_none() && kept.scope.is_none());
    let blank =
        parse_refresh_response(br#"{"access_token":"a","refresh_token":"","expires_in":3600}"#)
            .unwrap();
    assert!(blank.refresh_token.is_none());
    for body in [
        &br#"{"access_token":"","expires_in":3600}"#[..],
        br#"{"expires_in":3600}"#,
        br#"{"access_token":"a"}"#,
        br#"not json"#,
    ] {
        assert_eq!(
            parse_refresh_response(body).err(),
            Some(ClaudeSignInError::InvalidResponse)
        );
    }
}

fn stored_sign_in() -> ClaudeOAuthCredential {
    let (bundle, _) = crate::claude_oauth::import_tokens_at(
        crate::claude_oauth::ClaudeIssuedTokens {
            access_token: zeroize::Zeroizing::new("stored-access".into()),
            refresh_token: Some(zeroize::Zeroizing::new("stored-refresh".into())),
            expires_in: 28_800,
            refresh_token_expires_in: None,
            scope: Some("user:profile user:inference".into()),
        },
        crate::claude_oauth::ClaudeProfile::default(),
        1_800_000_000,
    )
    .unwrap()
    .into_parts();
    ClaudeOAuthCredential::parse(bundle.as_bytes()).unwrap()
}

#[tokio::test]
async fn the_broker_exchange_validates_rotation_and_classifies_refusals() {
    use crate::BrokerRequestError;
    use crate::refresh_failure::RefreshFailure;
    use crate::runtime::exchange_claude_oauth_refresh;

    // A rotation keeps the plan and is stored as the canonical envelope.
    let provider = ScriptedProvider::default();
    provider.answer(
        StatusCode::OK,
        json!({"access_token": "rotated", "expires_in": 3_600, "scope": "user:profile user:inference"}),
    );
    let bundle = exchange_claude_oauth_refresh(&provider, stored_sign_in(), 1_800_000_100)
        .await
        .map_err(|(failure, _)| failure)
        .unwrap();
    let rotated = ClaudeOAuthCredential::parse(bundle.as_bytes()).unwrap();
    assert_eq!(rotated.access_token(), "rotated");
    assert_eq!(rotated.refresh_token(), "stored-refresh");
    assert_eq!(rotated.expires_at_unix(), 1_800_003_700);
    assert_eq!(
        provider.sent()[0].json()["refresh_token"],
        json!("stored-refresh")
    );

    for (status, body, permanent) in [
        // A definite refusal of the refresh token.
        (
            StatusCode::BAD_REQUEST,
            json!({"error": "invalid_grant"}),
            true,
        ),
        (StatusCode::UNAUTHORIZED, json!({}), true),
        // An outage is uncertain, still terminal for the attempt.
        (StatusCode::SERVICE_UNAVAILABLE, json!({}), false),
    ] {
        let provider = ScriptedProvider::default();
        provider.answer(status, body);
        let (failure, error) =
            match exchange_claude_oauth_refresh(&provider, stored_sign_in(), 1_800_000_100).await {
                Ok(_) => panic!("{status} was accepted"),
                Err(failed) => failed,
            };
        match failure {
            RefreshFailure::Rejected(rejection) => assert_eq!(rejection.permanent, permanent),
            _ => panic!("{status} was not classified as a rejection"),
        }
        assert_eq!(
            error == BrokerRequestError::Denied,
            permanent,
            "{status}: {error:?}"
        );
    }

    // A success that drops the profile scope, adds one that can create API
    // keys, or has no lifetime, is refused.
    for body in [
        json!({"access_token": "rotated", "expires_in": 3_600, "scope": "user:inference"}),
        json!({"access_token": "rotated", "expires_in": 3_600, "scope": "user:profile user:inference org:create_api_key"}),
        json!({"access_token": "rotated"}),
        json!({"access_token": "", "expires_in": 3_600}),
    ] {
        let provider = ScriptedProvider::default();
        provider.answer(StatusCode::OK, body.clone());
        let failure =
            match exchange_claude_oauth_refresh(&provider, stored_sign_in(), 1_800_000_100).await {
                Ok(_) => panic!("{body} was accepted"),
                Err((failure, _)) => failure,
            };
        assert!(
            matches!(
                failure,
                RefreshFailure::Material | RefreshFailure::ResponseParse
            ),
            "{body}: {failure:?}"
        );
    }
}
