use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use bytes::Bytes;
use futures::stream;
use http::{HeaderMap, Method, StatusCode};
use url::Url;

use super::*;
use crate::antigravity_oauth::{ANTIGRAVITY_ALLOWED_SCOPES, AntigravityOAuthCredential};
use crate::{
    BrokerUpstreamError, BrokerUpstreamRequest, BrokerUpstreamResponse, BrokerUpstreamTransport,
};

struct RecordedRequest {
    method: Method,
    target: Url,
    headers: HeaderMap,
    body: Vec<u8>,
}

struct MockUpstream {
    recorded: Mutex<Vec<RecordedRequest>>,
    status: StatusCode,
    response_body: Vec<u8>,
}

impl MockUpstream {
    fn json(status: StatusCode, body: serde_json::Value) -> Arc<Self> {
        Arc::new(Self {
            recorded: Mutex::new(Vec::new()),
            status,
            response_body: serde_json::to_vec(&body).unwrap(),
        })
    }

    fn requests(&self) -> Vec<RecordedRequest> {
        std::mem::take(&mut *self.recorded.lock().unwrap())
    }
}

#[async_trait]
impl BrokerUpstreamTransport for MockUpstream {
    async fn execute(
        &self,
        request: BrokerUpstreamRequest,
    ) -> Result<BrokerUpstreamResponse, BrokerUpstreamError> {
        let (method, target, headers, body) = request.into_parts();
        self.recorded.lock().unwrap().push(RecordedRequest {
            method,
            target,
            headers,
            body,
        });
        let body = Bytes::from(self.response_body.clone());
        Ok(BrokerUpstreamResponse::new(
            self.status,
            HeaderMap::new(),
            Box::pin(stream::once(async move { Ok(body) })),
        ))
    }
}

fn synthetic_id_token(email: &str) -> String {
    let header =
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(br#"{"alg":"RS256","typ":"JWT"}"#);
    let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(
        serde_json::to_vec(&serde_json::json!({
            "iss": "https://accounts.google.com",
            "aud": ANTIGRAVITY_OAUTH_CLIENT_ID,
            "email": email,
        }))
        .unwrap(),
    );
    format!("{header}.{payload}.sig")
}

#[tokio::test]
async fn start_and_complete_accept_raw_code_callback_url_and_code_hash_state() {
    let token_response = serde_json::json!({
        "access_token": "ya29.synthetic_antigravity_access_token",
        "refresh_token": "1//0g_synthetic_antigravity_refresh_token",
        "expires_in": 3599,
        "scope": ANTIGRAVITY_ALLOWED_SCOPES.join(" "),
        "token_type": "Bearer",
        "id_token": synthetic_id_token("dev@example.com"),
    });
    let cases = [
        (
            "callback_url_with_state",
            "4/0AY_synthetic_code",
            Box::new(|state: &str| {
                format!(
                    "https://antigravity.google/oauth-callback?code=4/0AY_synthetic_code&state={state}"
                )
            }) as Box<dyn Fn(&str) -> String>,
        ),
        (
            "callback_url_without_state",
            "4/0AY_synthetic_code",
            Box::new(|_: &str| {
                "https://antigravity.google/oauth-callback?code=4/0AY_synthetic_code".to_owned()
            }),
        ),
        (
            "code_hash_state",
            "4/0AY_synthetic_code",
            Box::new(|state: &str| format!("4/0AY_synthetic_code#{state}")),
        ),
        (
            "raw_google_code",
            "4/0AanRRrt_example-code/with_slashes",
            Box::new(|_: &str| "  4/0AanRRrt_example-code/with_slashes  \n".to_owned()),
        ),
    ];
    for (label, expected_code, make_pasted) in cases {
        let upstream = MockUpstream::json(StatusCode::OK, token_response.clone());
        let sign_in = AntigravitySignIn::new(upstream.clone());
        let started = sign_in.start().unwrap();
        let parsed = Url::parse(started.authorize_url()).unwrap();
        assert_eq!(parsed.host_str(), Some("accounts.google.com"), "{label}");
        assert_eq!(parsed.path(), "/o/oauth2/auth", "{label}");
        let query: BTreeMap<String, String> = parsed.query_pairs().into_owned().collect();
        assert_eq!(
            query.get("client_id").map(String::as_str),
            Some(ANTIGRAVITY_OAUTH_CLIENT_ID),
            "{label}"
        );
        assert_eq!(
            query.get("redirect_uri").map(String::as_str),
            Some(ANTIGRAVITY_MANUAL_REDIRECT_URL),
            "{label}"
        );
        assert_eq!(
            query.get("code_challenge_method").map(String::as_str),
            Some("S256"),
            "{label}"
        );
        let state = query.get("state").unwrap();

        let pasted = make_pasted(state);
        let import = sign_in
            .complete(started.handle(), &pasted)
            .await
            .unwrap_or_else(|err| panic!("{label}: unexpected error {err:?}"));
        let (bundle, account_hint) = import.into_parts();
        assert_eq!(account_hint.as_deref(), Some("dev@example.com"), "{label}");
        let stored = AntigravityOAuthCredential::parse(bundle.as_bytes()).unwrap();
        assert_eq!(
            stored.access_token(),
            "ya29.synthetic_antigravity_access_token",
            "{label}"
        );
        assert_eq!(
            stored.refresh_token(),
            "1//0g_synthetic_antigravity_refresh_token",
            "{label}"
        );
        // Signed id_token must never be stored in the canonical envelope.
        assert!(
            !std::str::from_utf8(bundle.as_bytes())
                .unwrap()
                .contains("eyJ"),
            "{label}"
        );

        let requests = upstream.requests();
        assert_eq!(requests.len(), 1, "{label}");
        assert_eq!(requests[0].method, Method::POST, "{label}");
        assert_eq!(requests[0].target.as_str(), GOOGLE_TOKEN_URL, "{label}");
        assert_eq!(
            requests[0]
                .headers
                .get(header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok()),
            Some("application/x-www-form-urlencoded"),
            "{label}"
        );
        let form: BTreeMap<String, String> = url::form_urlencoded::parse(&requests[0].body)
            .into_owned()
            .collect();
        assert_eq!(
            form.get("client_id").map(String::as_str),
            Some(ANTIGRAVITY_OAUTH_CLIENT_ID),
            "{label}"
        );
        assert_eq!(
            form.get("client_secret").map(String::as_str),
            Some(ANTIGRAVITY_OAUTH_CLIENT_SECRET),
            "{label}"
        );
        assert_eq!(
            form.get("code").map(String::as_str),
            Some(expected_code),
            "{label}"
        );
        assert!(
            form.get("code_verifier").is_some_and(|v| !v.is_empty()),
            "{label}"
        );
    }
}

#[test]
fn parse_pasted_code_refuses_wrong_state_malformed_urls_and_invalid_inputs() {
    let expected_state = "abcdefghijklmnopqrstuvwxyz0123456789_-ABCDE";
    let oversized_code = "a".repeat(MAX_CODE_BYTES + 1);
    let oversized_paste = format!(
        "https://antigravity.google/oauth-callback?code={}&state={expected_state}",
        "a".repeat(MAX_PASTE_BYTES)
    );
    let url_wrong_state =
        "https://antigravity.google/oauth-callback?code=4/0AY_synthetic_code&state=wrong-state";
    let url_empty_state =
        "https://antigravity.google/oauth-callback?code=4/0AY_synthetic_code&state=";
    let url_dup_code = format!(
        "https://antigravity.google/oauth-callback?code=4/0A1&code=4/0A2&state={expected_state}"
    );
    let url_dup_state = format!(
        "https://antigravity.google/oauth-callback?code=4/0A1&state={expected_state}&state={expected_state}"
    );
    for invalid in [
        "",
        "   ",
        "\t\r\n",
        "4/0AY_synthetic_code#wrong-state",
        "4/0AY_synthetic_code#",
        "#state_only",
        "4/0AY_synthetic_code#part1#part2",
        url_wrong_state,
        url_empty_state,
        url_dup_code.as_str(),
        url_dup_state.as_str(),
        "https://antigravity.google/oauth-callback",
        "https://antigravity.google/oauth-callback?state=only-state",
        "https://antigravity.google/oauth-callback?code=",
        "https://[::1",
        "ftp://antigravity.google/oauth-callback?code=4/0AY",
        "https:antigravity.google/oauth-callback",
        "antigravity.google/oauth-callback?code=4/0AY",
        "4/0AY with spaces",
        "4/0AY\ncode",
        "4/0AY\x00code",
        "4/0AY_non_ascii_é",
        oversized_code.as_str(),
        oversized_paste.as_str(),
    ] {
        assert_eq!(
            parse_pasted_code(invalid, expected_state).err(),
            Some(AntigravitySignInError::InvalidCode),
            "expected refusal for {invalid:?}"
        );
    }
}

#[tokio::test]
async fn complete_refuses_state_mismatch_and_out_of_allowlist_scope() {
    let upstream = MockUpstream::json(
        StatusCode::OK,
        serde_json::json!({
            "access_token": "ya29.synthetic_antigravity_access_token",
            "refresh_token": "1//0g_synthetic_antigravity_refresh_token",
            "expires_in": 3599,
            "scope": format!("{} https://www.googleapis.com/auth/drive", ANTIGRAVITY_ALLOWED_SCOPES.join(" ")),
        }),
    );
    let sign_in = AntigravitySignIn::new(upstream.clone());
    let started = sign_in.start().unwrap();
    let err = match sign_in
        .complete(started.handle(), "4/0AY_synthetic_code#wrong-state")
        .await
    {
        Ok(_) => panic!("expected InvalidCode"),
        Err(err) => err,
    };
    assert_eq!(err, AntigravitySignInError::InvalidCode);
    assert!(upstream.requests().is_empty());

    let parsed = Url::parse(started.authorize_url()).unwrap();
    let state = parsed
        .query_pairs()
        .find_map(|(k, v)| (k == "state").then(|| v.into_owned()))
        .unwrap();
    let err = match sign_in
        .complete(started.handle(), &format!("4/0AY_synthetic_code#{state}"))
        .await
    {
        Ok(_) => panic!("expected InvalidResponse"),
        Err(err) => err,
    };
    assert_eq!(err, AntigravitySignInError::InvalidResponse);
}

#[tokio::test]
async fn revoke_stored_sends_body_only_token_without_client_secret() {
    let upstream = MockUpstream::json(StatusCode::OK, serde_json::json!({}));
    let import = crate::antigravity_oauth::import_antigravity_tokens(
        crate::antigravity_oauth::AntigravityIssuedTokens {
            access_token: Zeroizing::new("ya29.synthetic_access".to_owned()),
            refresh_token: Some(Zeroizing::new("1//0g_synthetic_refresh".to_owned())),
            expires_in: 3600,
            scope: Some(ANTIGRAVITY_ALLOWED_SCOPES.join(" ")),
            id_token: None,
        },
    )
    .unwrap();
    let (bundle, _) = import.into_parts();
    let transport: Arc<dyn BrokerUpstreamTransport> = upstream.clone();
    let result = revoke_stored(&transport, bundle.as_bytes()).await;
    assert_eq!(result, ProviderRevocation::Confirmed);
    let requests = upstream.requests();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].method, Method::POST);
    assert_eq!(requests[0].target.as_str(), GOOGLE_REVOKE_URL);
    assert!(requests[0].target.query().is_none());
    let form: BTreeMap<String, String> = url::form_urlencoded::parse(&requests[0].body)
        .into_owned()
        .collect();
    assert_eq!(form.len(), 1);
    assert_eq!(
        form.get("token").map(String::as_str),
        Some("1//0g_synthetic_refresh")
    );
    assert!(!form.contains_key("client_secret"));
    assert!(!form.contains_key("client_id"));
}
