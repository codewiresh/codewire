//! The featured smoke build's synthetic Codex and GitHub App sign-ins and
//! their refreshes (#5539), beside Claude's in `synthetic_claude.rs`.
//!
//! The rules are Claude's. Every token is a fixed prefix, this boot's id and
//! 16 hex characters from the OS random generator. Only that shape is
//! accepted, a refresh token is spent once in this process, nothing is
//! forwarded and no token is logged. The broker's Landlock domain denies the
//! boot id, so a refresh's tokens carry the presented token's boot id and the
//! broker checks shape alone.
//!
//! A synthetic Codex access token is an unsigned JWT whose third segment is
//! the plain `cwlocalbroker` canary: its `exp` makes the first use refresh
//! it, and the smokes' boot-id scan still finds the canary. Only this module
//! recognizes that form, and a release never compiles it
//! (`NON_SHIPPING_INPUTS` in `scripts/ci/release/cw_release.py`).
//!
//! GitHub's token prefixes are built from parts, so no committed literal
//! reads as a GitHub token.

use std::collections::BTreeSet;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use bytes::Bytes;
use futures::stream;
use http::{HeaderMap, HeaderValue, Method, StatusCode};
use rand::RngCore as _;
use serde_json::{Value, json};

use super::synthetic_values::{self, canary};
use super::{BrokerUpstreamError, BrokerUpstreamResponse, SYNTHETIC_CODEX_ACCOUNT_ID};
use crate::provider_oauth::github::CODEWIRE_GITHUB_APP_CLIENT_ID;
use crate::provider_oauth::{CODEX_OAUTH_CLIENT_ID, OPENAI_TOKEN_URL};

const GITHUB_TOKEN_URL: &str = "https://github.com/login/oauth/access_token";
/// The Codex access token's canary, its JWT's third segment.
const CODEX_ACCESS_CANARY: &str = "cwlocalbroker";
const CODEX_REFRESH_PREFIX: &str = "cwlocalrefresh";
/// What follows `ghu_` or `ghr_` in a synthetic GitHub token.
const GITHUB_MARKER: &str = "cwlocalgithub";
/// A first access token lasts just past the brokers' five-minute refresh
/// margin, so its first use refreshes it; a refreshed one lasts a working day.
const FIRST_LIFETIME_SECONDS: u64 = 301;
const REFRESHED_LIFETIME_SECONDS: u64 = 8 * 60 * 60;
/// GitHub's own refresh-token lifetime for an App user token.
const GITHUB_REFRESH_LIFETIME_SECONDS: u64 = 15_897_600;
const MAX_BODY_BYTES: usize = 64 * 1024;

/// The refresh tokens this process has accepted once.
static SPENT_REFRESH_TOKENS: Mutex<BTreeSet<String>> = Mutex::new(BTreeSet::new());

/// The product smoke's Codex and GitHub device logins, approved at the first
/// poll, and their refreshes. `None` is a request of neither.
pub(super) fn answer(
    method: &Method,
    target: &url::Url,
    headers: &HeaderMap,
    body: &[u8],
) -> Result<Option<BrokerUpstreamResponse>, BrokerUpstreamError> {
    let form = |name: &str| {
        url::form_urlencoded::parse(body)
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.into_owned())
    };
    let grant = |name: &str| form("grant_type").as_deref() == Some(name);
    let value = match (method.as_str(), target.as_str()) {
        ("POST", "https://auth.openai.com/api/accounts/deviceauth/usercode") => {
            json!({"device_auth_id": "synthetic-smoke", "user_code": "SYNTH-ETIC", "interval": "1"})
        }
        ("POST", "https://auth.openai.com/api/accounts/deviceauth/token") => {
            json!({"authorization_code": "synthetic-smoke",
                "code_challenge": "synthetic-smoke", "code_verifier": "synthetic-smoke"})
        }
        ("POST", OPENAI_TOKEN_URL) if grant("authorization_code") => {
            codex_tokens(&synthetic_values::boot_id()?, FIRST_LIFETIME_SECONDS)?
        }
        ("POST", OPENAI_TOKEN_URL) => return codex_refresh(headers, body).map(Some),
        ("POST", "https://github.com/login/device/code") => {
            json!({"device_code": "synthetic-smoke", "user_code": "SYNTH-ETIC",
                "expires_in": 900, "interval": 1})
        }
        ("POST", GITHUB_TOKEN_URL) if grant("urn:ietf:params:oauth:grant-type:device_code") => {
            github_tokens(&synthetic_values::boot_id()?, FIRST_LIFETIME_SECONDS)
        }
        ("POST", GITHUB_TOKEN_URL) if grant("refresh_token") => {
            if form("client_id").as_deref() != Some(CODEWIRE_GITHUB_APP_CLIENT_ID)
                || form("client_secret").is_some()
                || body.len() > MAX_BODY_BYTES
            {
                return Ok(Some(github_refused()));
            }
            let presented = form("refresh_token").unwrap_or_default();
            match spend(&presented, &github_prefix('r'))? {
                Some(boot) => github_tokens(&boot, REFRESHED_LIFETIME_SECONDS),
                None => return Ok(Some(github_refused())),
            }
        }
        ("GET", "https://api.github.com/user") => json!({"id": 1, "login": "synthetic-smoke"}),
        ("GET", "https://api.github.com/user/installations?per_page=100&page=1") => {
            json!({"installations": [{"id": 1,
                "app_slug": crate::provider_oauth::github::CODEWIRE_GITHUB_APP_SLUG}]})
        }
        _ => return Ok(None),
    };
    Ok(Some(json_answer(StatusCode::OK, &value)))
}

/// Whether `value` is a synthetic Codex access token: the opaque
/// `cwlocalbroker` canary a smoke imports, or this module's JWT form.
pub(super) fn codex_bearer(value: &str) -> bool {
    canary(value, CODEX_ACCESS_CANARY) || codex_jwt(value)
}

/// The JWT form exactly: a header of `{"alg":"none"}`, a payload of `iat`,
/// `exp` and a 16-hex `jti` and nothing else, and the canary as signature.
fn codex_jwt(value: &str) -> bool {
    let mut parts = value.split('.');
    let (Some(header), Some(payload), Some(signature), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return false;
    };
    let decode = |segment: &str| {
        base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(segment)
            .ok()
            .and_then(|bytes| serde_json::from_slice::<Value>(&bytes).ok())
    };
    let claims = decode(payload);
    let claims = claims.as_ref().and_then(Value::as_object);
    canary(signature, CODEX_ACCESS_CANARY)
        && decode(header) == Some(json!({"alg": "none"}))
        && claims.is_some_and(|claims| {
            let number = |name: &str| claims.get(name).and_then(Value::as_u64);
            claims.len() == 3
                && matches!((number("iat"), number("exp")), (Some(iat), Some(exp)) if exp > iat)
                && claims
                    .get("jti")
                    .and_then(Value::as_str)
                    .is_some_and(|jti| jti.len() == 16 && lower_hex(jti))
        })
}

/// The broker's Codex refresh: JSON, Codex's client id, and a refresh token
/// of this module's shape presented for the first time.
fn codex_refresh(
    headers: &HeaderMap,
    body: &[u8],
) -> Result<BrokerUpstreamResponse, BrokerUpstreamError> {
    if headers.get("content-type").map(HeaderValue::as_bytes) != Some(b"application/json")
        || body.len() > MAX_BODY_BYTES
    {
        return Err(BrokerUpstreamError::Protocol);
    }
    let request: Value = serde_json::from_slice(body).map_err(|_| BrokerUpstreamError::Protocol)?;
    let text = |field: &str| request.get(field).and_then(Value::as_str);
    if text("client_id") != Some(CODEX_OAUTH_CLIENT_ID)
        || text("grant_type") != Some("refresh_token")
    {
        return Ok(codex_refused());
    }
    match spend(
        text("refresh_token").unwrap_or_default(),
        CODEX_REFRESH_PREFIX,
    )? {
        Some(boot) => Ok(json_answer(
            StatusCode::OK,
            &codex_tokens(&boot, REFRESHED_LIFETIME_SECONDS)?,
        )),
        None => Ok(codex_refused()),
    }
}

/// A Codex token answer: the sign-in's ID token, an access token lasting
/// `lifetime` and a new refresh token, all for `boot`.
fn codex_tokens(boot: &str, lifetime: u64) -> Result<Value, BrokerUpstreamError> {
    let encode = |value: Value| {
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(value.to_string().as_bytes())
    };
    let now = now_unix()?;
    let id_token = format!(
        "{}.{}.synthetic-signature",
        encode(json!({"alg": "none"})),
        encode(json!({"email": "native-smoke@example.test",
            "https://api.openai.com/auth": {
                "chatgpt_account_id": SYNTHETIC_CODEX_ACCOUNT_ID,
                "chatgpt_account_is_fedramp": false}})),
    );
    let access_token = format!(
        "{}.{}.{CODEX_ACCESS_CANARY}{boot}",
        encode(json!({"alg": "none"})),
        encode(json!({"iat": now, "exp": now + lifetime, "jti": random_hex()})),
    );
    Ok(json!({
        "id_token": id_token,
        "access_token": access_token,
        "refresh_token": format!("{CODEX_REFRESH_PREFIX}{boot}{}", random_hex()),
    }))
}

/// A GitHub App user-token answer for `boot`, its access token lasting
/// `lifetime`.
fn github_tokens(boot: &str, lifetime: u64) -> Value {
    json!({
        "access_token": format!("{}{boot}{}", github_prefix('u'), random_hex()),
        "token_type": "bearer",
        "scope": "",
        "expires_in": lifetime,
        "refresh_token": format!("{}{boot}{}", github_prefix('r'), random_hex()),
        "refresh_token_expires_in": GITHUB_REFRESH_LIFETIME_SECONDS,
    })
}

/// `gh`, the token kind, `_` and the marker.
fn github_prefix(kind: char) -> String {
    format!("gh{kind}_{GITHUB_MARKER}")
}

/// Spend `token` if it is `prefix`, a boot id and, when this module minted
/// it, 16 more hex characters, and was not presented before. Returns its
/// boot id.
fn spend(token: &str, prefix: &str) -> Result<Option<String>, BrokerUpstreamError> {
    let Some(rest) = token.strip_prefix(prefix) else {
        return Ok(None);
    };
    if !matches!(rest.len(), 32 | 48) || !lower_hex(rest) {
        return Ok(None);
    }
    let first_use = SPENT_REFRESH_TOKENS
        .lock()
        .map_err(|_| BrokerUpstreamError::Protocol)?
        .insert(token.to_owned());
    Ok(first_use.then(|| rest[..32].to_owned()))
}

fn codex_refused() -> BrokerUpstreamResponse {
    json_answer(
        StatusCode::BAD_REQUEST,
        &json!({"error": "invalid_grant", "error_description": "Synthetic smoke refusal"}),
    )
}

/// GitHub answers a refused refresh with 200 and an error code.
fn github_refused() -> BrokerUpstreamResponse {
    json_answer(
        StatusCode::OK,
        &json!({"error": "bad_refresh_token", "error_description": "Synthetic smoke refusal"}),
    )
}

fn json_answer(status: StatusCode, value: &Value) -> BrokerUpstreamResponse {
    let mut headers = HeaderMap::new();
    headers.insert("content-type", HeaderValue::from_static("application/json"));
    let body = Bytes::from(value.to_string());
    BrokerUpstreamResponse::new(status, headers, Box::pin(stream::iter([Ok(body)])))
}

fn random_hex() -> String {
    let mut random = [0_u8; 8];
    rand::rngs::OsRng.fill_bytes(&mut random);
    random.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn lower_hex(value: &str) -> bool {
    value
        .bytes()
        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn now_unix() -> Result<u64, BrokerUpstreamError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .map_err(|_| BrokerUpstreamError::Protocol)
}

#[cfg(test)]
mod tests {
    use futures::StreamExt as _;
    use zeroize::Zeroizing;

    use super::*;
    use crate::codex_oauth::{CodexOAuthCredential, import_codex_tokens_at};
    use crate::github_app::TokenResponse;

    const BOOT: &str = "0123456789abcdef0123456789abcdef";

    fn url(value: &str) -> url::Url {
        url::Url::parse(value).unwrap()
    }

    fn json_headers() -> HeaderMap {
        HeaderMap::from_iter([(
            http::header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        )])
    }

    async fn read(response: BrokerUpstreamResponse) -> (StatusCode, Value) {
        let (status, _, mut body) = response.into_parts();
        let mut bytes = Vec::new();
        while let Some(chunk) = body.next().await {
            bytes.extend_from_slice(&chunk.unwrap());
        }
        (status, serde_json::from_slice(&bytes).unwrap())
    }

    async fn post(target: &str, headers: &HeaderMap, body: &[u8]) -> (StatusCode, Value) {
        let answer = answer(&Method::POST, &url(target), headers, body).unwrap();
        read(answer.expect("answered")).await
    }

    fn codex_refresh_body(refresh_token: &str) -> Vec<u8> {
        serde_json::to_vec(&json!({"client_id": CODEX_OAUTH_CLIENT_ID,
            "grant_type": "refresh_token", "refresh_token": refresh_token}))
        .unwrap()
    }

    fn github_refresh_body(refresh_token: &str, extra: &[(&str, &str)]) -> Vec<u8> {
        let mut form = url::form_urlencoded::Serializer::new(String::new());
        form.append_pair("client_id", CODEWIRE_GITHUB_APP_CLIENT_ID);
        for (key, value) in extra {
            form.append_pair(key, value);
        }
        form.append_pair("grant_type", "refresh_token");
        form.append_pair("refresh_token", refresh_token);
        form.finish().into_bytes()
    }

    fn codex_credential(tokens: &Value, at: u64) -> CodexOAuthCredential {
        let token = |name: &str| Zeroizing::new(tokens[name].as_str().unwrap().to_owned());
        let import = import_codex_tokens_at(
            token("id_token"),
            token("access_token"),
            token("refresh_token"),
            at,
        )
        .unwrap();
        CodexOAuthCredential::parse(import.into_parts().0.as_bytes()).unwrap()
    }

    #[tokio::test]
    async fn a_codex_sign_in_is_due_at_first_use_and_refreshes_once() {
        let first = codex_tokens(BOOT, FIRST_LIFETIME_SECONDS).unwrap();
        let now = now_unix().unwrap();
        let credential = codex_credential(&first, now);
        assert!(!credential.should_refresh(now));
        assert!(credential.should_refresh(now + 2));
        assert!(codex_bearer(first["access_token"].as_str().unwrap()));

        let refresh = first["refresh_token"].as_str().unwrap();
        let (status, refreshed) = post(
            OPENAI_TOKEN_URL,
            &json_headers(),
            &codex_refresh_body(refresh),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let access = refreshed["access_token"].as_str().unwrap();
        assert!(codex_bearer(access));
        assert!(access.ends_with(&format!("{CODEX_ACCESS_CANARY}{BOOT}")));
        assert!(!codex_credential(&refreshed, now).should_refresh(now + 60 * 60));

        let (status, again) = post(
            OPENAI_TOKEN_URL,
            &json_headers(),
            &codex_refresh_body(refresh),
        )
        .await;
        assert_eq!(
            (status, again["error"].as_str()),
            (StatusCode::BAD_REQUEST, Some("invalid_grant"))
        );
    }

    #[tokio::test]
    async fn a_refresh_token_of_another_shape_is_refused() {
        let random = random_hex();
        for token in [
            format!("cwlocalrefres{BOOT}{random}"),
            format!("{CODEX_REFRESH_PREFIX}{}", &BOOT[..31]),
            format!("{CODEX_REFRESH_PREFIX}{BOOT}{}", &random[..15]),
            format!("{CODEX_REFRESH_PREFIX}{}{random}", BOOT.to_uppercase()),
            format!("{}{BOOT}{random}", github_prefix('r')),
        ] {
            let (status, answer) = post(
                OPENAI_TOKEN_URL,
                &json_headers(),
                &codex_refresh_body(&token),
            )
            .await;
            assert_eq!(
                (status, answer["error"].as_str()),
                (StatusCode::BAD_REQUEST, Some("invalid_grant")),
                "{token}"
            );
        }
        let token = format!("{CODEX_REFRESH_PREFIX}{BOOT}{random}");
        let mut wrong_client: Value = serde_json::from_slice(&codex_refresh_body(&token)).unwrap();
        wrong_client["client_id"] = "app_other".into();
        let (status, _) = post(
            OPENAI_TOKEN_URL,
            &json_headers(),
            &serde_json::to_vec(&wrong_client).unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(matches!(
            answer(
                &Method::POST,
                &url(OPENAI_TOKEN_URL),
                &HeaderMap::new(),
                &codex_refresh_body(&token)
            ),
            Err(BrokerUpstreamError::Protocol)
        ));
    }

    #[test]
    fn only_this_modules_jwt_form_is_a_codex_bearer() {
        let encode = |value: Value| {
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(value.to_string().as_bytes())
        };
        let header = encode(json!({"alg": "none"}));
        let claims = encode(json!({"iat": 1, "exp": 302, "jti": random_hex()}));
        let jwt =
            |header: &str, claims: &str, signature: &str| format!("{header}.{claims}.{signature}");
        let canary = format!("{CODEX_ACCESS_CANARY}{BOOT}");
        assert!(codex_bearer(&jwt(&header, &claims, &canary)));
        assert!(codex_bearer(&canary));
        for signature in [
            format!("cwlocalopenai{BOOT}"),
            format!("{CODEX_ACCESS_CANARY}{}", &BOOT[..31]),
            format!("{canary}0"),
            format!("{CODEX_ACCESS_CANARY}{}", BOOT.to_uppercase()),
            "synthetic-signature".to_owned(),
        ] {
            assert!(
                !codex_bearer(&jwt(&header, &claims, &signature)),
                "{signature}"
            );
        }
        for (header, claims) in [
            (encode(json!({"alg": "HS256"})), claims.clone()),
            (encode(json!({"alg": "none", "typ": "JWT"})), claims.clone()),
            (header.clone(), encode(json!({"iat": 1, "exp": 302}))),
            (
                header.clone(),
                encode(json!({"iat": 302, "exp": 1, "jti": random_hex()})),
            ),
            (
                header.clone(),
                encode(json!({"iat": 1, "exp": 302, "jti": random_hex(), "sub": "x"})),
            ),
        ] {
            assert!(
                !codex_bearer(&jwt(&header, &claims, &canary)),
                "{header}.{claims}"
            );
        }
        assert!(!codex_bearer(&format!(
            "{}.{canary}",
            jwt(&header, &claims, &canary)
        )));
    }

    #[tokio::test]
    async fn a_github_sign_in_expires_and_refreshes_once() {
        let first = github_tokens(BOOT, FIRST_LIFETIME_SECONDS);
        let response: TokenResponse = serde_json::from_value(first.clone()).unwrap();
        assert!(response.is_user_token());
        assert_eq!(first["expires_in"], FIRST_LIFETIME_SECONDS);

        let refresh = first["refresh_token"].as_str().unwrap();
        let (status, refreshed) = post(
            GITHUB_TOKEN_URL,
            &HeaderMap::new(),
            &github_refresh_body(refresh, &[]),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(refreshed["expires_in"], REFRESHED_LIFETIME_SECONDS);
        let response: TokenResponse = serde_json::from_value(refreshed.clone()).unwrap();
        assert!(response.is_user_token());
        assert!(
            refreshed["access_token"]
                .as_str()
                .unwrap()
                .starts_with(&format!("{}{BOOT}", github_prefix('u')))
        );
        assert_ne!(refreshed["refresh_token"].as_str(), Some(refresh));

        let (_, again) = post(
            GITHUB_TOKEN_URL,
            &HeaderMap::new(),
            &github_refresh_body(refresh, &[]),
        )
        .await;
        assert_eq!(again["error"].as_str(), Some("bad_refresh_token"));
    }

    #[tokio::test]
    async fn a_github_refresh_with_a_secret_or_another_shape_is_refused() {
        let token = format!("{}{BOOT}{}", github_prefix('r'), random_hex());
        let secret = github_refresh_body(&token, &[("client_secret", "synthetic")]);
        let (_, answer) = post(GITHUB_TOKEN_URL, &HeaderMap::new(), &secret).await;
        assert_eq!(answer["error"].as_str(), Some("bad_refresh_token"));
        for other in [
            format!("{}{BOOT}{}", github_prefix('u'), random_hex()),
            format!("{CODEX_REFRESH_PREFIX}{BOOT}{}", random_hex()),
            format!("{}{}", github_prefix('r'), &BOOT[..30]),
        ] {
            let (_, answer) = post(
                GITHUB_TOKEN_URL,
                &HeaderMap::new(),
                &github_refresh_body(&other, &[]),
            )
            .await;
            assert_eq!(
                answer["error"].as_str(),
                Some("bad_refresh_token"),
                "{other}"
            );
        }
        // The token refused for its secret was never spent.
        let (status, answer) = post(
            GITHUB_TOKEN_URL,
            &HeaderMap::new(),
            &github_refresh_body(&token, &[]),
        )
        .await;
        assert_eq!((status, answer.get("error")), (StatusCode::OK, None));
    }
}
