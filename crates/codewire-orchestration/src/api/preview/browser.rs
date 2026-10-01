//! Guard primitives for the dedicated preview-host browser authorization.
//! Codes/grants are opaque, purpose-separated, and never account tokens.
use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, Payload},
};
use axum::http::{HeaderMap, Method, header};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use url::Url;

const START_PURPOSE: &[u8] = b"codewire-preview-start-v1";

fn start_key(secret: &str) -> [u8; 32] {
    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).expect("HMAC key");
    mac.update(START_PURPOSE);
    mac.finalize().into_bytes().into()
}

/// Only a short-lived request continuation, never account or preview access.
/// Encrypt the return path so application query values are not URL-readable.
pub(super) fn seal_start<T: serde::Serialize>(secret: &str, value: &T) -> Result<String, ()> {
    let plain = serde_json::to_vec(value).map_err(|_| ())?;
    if plain.len() > 4096 {
        return Err(());
    }
    let cipher =
        <Aes256Gcm as aes_gcm::KeyInit>::new_from_slice(&start_key(secret)).map_err(|_| ())?;
    let mut nonce = [0u8; 12];
    getrandom::fill(&mut nonce).map_err(|_| ())?;
    let encrypted = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: &plain,
                aad: START_PURPOSE,
            },
        )
        .map_err(|_| ())?;
    let mut bytes = Vec::with_capacity(13 + encrypted.len());
    bytes.push(1);
    bytes.extend_from_slice(&nonce);
    bytes.extend_from_slice(&encrypted);
    Ok(URL_SAFE_NO_PAD.encode(bytes))
}

pub(super) fn open_start<T: serde::de::DeserializeOwned>(
    secret: &str,
    value: &str,
) -> Result<T, ()> {
    if value.len() > 5500 {
        return Err(());
    }
    let bytes = URL_SAFE_NO_PAD.decode(value).map_err(|_| ())?;
    if bytes.len() < 30 || bytes[0] != 1 {
        return Err(());
    }
    let cipher =
        <Aes256Gcm as aes_gcm::KeyInit>::new_from_slice(&start_key(secret)).map_err(|_| ())?;
    let plain = cipher
        .decrypt(
            Nonce::from_slice(&bytes[1..13]),
            Payload {
                msg: &bytes[13..],
                aad: START_PURPOSE,
            },
        )
        .map_err(|_| ())?;
    serde_json::from_slice(&plain).map_err(|_| ())
}

pub(super) const AUTHORIZE_PATH: &str = "/api/v1/preview-auth/authorize";
pub(super) const CALLBACK_PATH: &str = "/.codewire/preview-auth/callback";
pub(super) const NONCE_COOKIE: &str = "__Host-codewire-preview-challenge";
pub(super) const GRANT_COOKIE: &str = "__Host-codewire-preview";

pub(super) fn random_token() -> Result<String, ()> {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes).map_err(|_| ())?;
    Ok(URL_SAFE_NO_PAD.encode(bytes))
}

pub(super) fn token_hash(token: &str) -> String {
    format!("{:x}", Sha256::digest(token.as_bytes()))
}

/// Reissuing access for the same live account session and preview must not
/// accumulate orphaned grants when a browser has discarded its cookie.
pub(super) fn scoped_grant_token(
    secret: &str,
    session: &str,
    organization: &str,
    environment: &str,
    port: &str,
    host: &str,
) -> String {
    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).expect("HMAC key");
    mac.update(b"codewire-preview-grant-v1\0");
    for field in [session, organization, environment, port, host] {
        mac.update(&(field.len() as u64).to_be_bytes());
        mac.update(field.as_bytes());
    }
    URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes())
}

pub(super) fn opaque_token(token: &str) -> bool {
    token.len() == 43
        && URL_SAFE_NO_PAD
            .decode(token)
            .is_ok_and(|bytes| bytes.len() == 32)
}

/// Cookies are authority: duplicates cannot select first/last by accident.
pub(super) fn unique_cookie<'a>(
    headers: &'a HeaderMap,
    expected: &str,
) -> Result<Option<&'a str>, ()> {
    let mut result = None;
    let mut total = 0usize;
    for header in headers.get_all(header::COOKIE) {
        total = total.checked_add(header.as_bytes().len()).ok_or(())?;
        if total > 16 * 1024 {
            return Err(());
        }
        for pair in header.to_str().map_err(|_| ())?.split(';') {
            let Some((name, value)) = pair.trim().split_once('=') else {
                continue;
            };
            if name.trim() == expected {
                if result.is_some() || value.is_empty() {
                    return Err(());
                }
                result = Some(value);
            }
        }
    }
    Ok(result)
}

pub(super) fn exact_origin(headers: &HeaderMap, expected: &str) -> bool {
    let mut values = headers.get_all(header::ORIGIN).iter();
    matches!(values.next().and_then(|value| value.to_str().ok()), Some(value) if value == expected)
        && values.next().is_none()
}

pub(super) fn frontend_origin(configured: &str) -> Result<String, ()> {
    let url = Url::parse(configured).map_err(|_| ())?;
    if url.scheme() != "https"
        || !url.username().is_empty()
        || url.password().is_some()
        || url.path() != "/"
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(());
    }
    Ok(url.origin().ascii_serialization())
}

/// The dashboard origin must sit outside the preview domain; a workload on a
/// sibling preview host could otherwise read or plant its cookies.
pub(super) fn preview_frontend_origin(
    configured: &str,
    preview_base_domain: &str,
) -> Result<String, ()> {
    let origin = frontend_origin(configured)?;
    let host = Url::parse(&origin)
        .ok()
        .and_then(|url| url.host_str().map(str::to_ascii_lowercase))
        .ok_or(())?;
    let base = preview_base_domain
        .trim()
        .trim_end_matches('.')
        .to_ascii_lowercase();
    if base.is_empty() || host == base || host.ends_with(&format!(".{base}")) {
        return Err(());
    }
    Ok(origin)
}

pub(super) fn safe_return_path(path: &str) -> bool {
    if path.len() > 2048
        || !path.starts_with('/')
        || path.starts_with("//")
        || path.contains('\\')
        || path.contains('#')
        || path.bytes().any(|byte| byte.is_ascii_control())
    {
        return false;
    }
    let Ok(url) = Url::parse(&format!("https://preview.invalid{path}")) else {
        return false;
    };
    url.origin().ascii_serialization() == "https://preview.invalid"
        && !url.path().starts_with("/.codewire/")
        && !url.path().starts_with("//")
}

pub(super) fn confirmation_token(secret: &str, session: &str, challenge: &str) -> String {
    let mut mac =
        Hmac::<Sha256>::new_from_slice(secret.as_bytes()).expect("HMAC accepts all key sizes");
    mac.update(b"codewire-preview-confirmation-v1\0");
    mac.update(session.as_bytes());
    mac.update(b"\0");
    mac.update(challenge.as_bytes());
    URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes())
}

pub(super) fn verify_confirmation(
    secret: &str,
    session: &str,
    challenge: &str,
    token: &str,
) -> bool {
    if token.len() != 43 {
        return false;
    }
    let Ok(bytes) = URL_SAFE_NO_PAD.decode(token) else {
        return false;
    };
    let mut mac =
        Hmac::<Sha256>::new_from_slice(secret.as_bytes()).expect("HMAC accepts all key sizes");
    mac.update(b"codewire-preview-confirmation-v1\0");
    mac.update(session.as_bytes());
    mac.update(b"\0");
    mac.update(challenge.as_bytes());
    mac.verify_slice(&bytes).is_ok()
}

pub(super) fn safe_cookie_request(method: &Method, headers: &HeaderMap, origin: &str) -> bool {
    matches!(*method, Method::GET | Method::HEAD | Method::OPTIONS) || exact_origin(headers, origin)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    #[test]
    fn start_continuation_is_encrypted_authenticated_and_bounded() {
        let value = serde_json::json!({"return_path": "/?private=query-canary"});
        let token = seal_start("synthetic-key", &value).unwrap();
        assert_eq!(
            open_start::<serde_json::Value>("synthetic-key", &token),
            Ok(value.clone())
        );
        assert_ne!(token, seal_start("synthetic-key", &value).unwrap());
        let mut bytes = URL_SAFE_NO_PAD.decode(&token).unwrap();
        assert!(
            !bytes
                .windows(b"query-canary".len())
                .any(|part| part == b"query-canary")
        );
        assert!(open_start::<serde_json::Value>("other-key", &token).is_err());
        let last = bytes.len() - 1;
        bytes[last] ^= 1;
        assert!(
            open_start::<serde_json::Value>("synthetic-key", &URL_SAFE_NO_PAD.encode(&bytes))
                .is_err()
        );
        bytes[0] = 2;
        assert!(
            open_start::<serde_json::Value>("synthetic-key", &URL_SAFE_NO_PAD.encode(&bytes))
                .is_err()
        );
        assert!(seal_start("synthetic-key", &"x".repeat(4097)).is_err());
        for invalid in [
            "".to_owned(),
            "x".repeat(5501),
            URL_SAFE_NO_PAD.encode([1u8; 29]),
        ] {
            assert!(open_start::<serde_json::Value>("synthetic-key", &invalid).is_err());
        }
    }

    #[test]
    fn full_entropy_opaque_values_and_digests_are_distinct() {
        let one = random_token().unwrap();
        let two = random_token().unwrap();
        assert!(opaque_token(&one));
        assert!(opaque_token(&two));
        assert_ne!(one, two);
        assert_eq!(token_hash(&one).len(), 64);
        assert_ne!(token_hash(&one), token_hash(&two));
        for invalid in [
            "",
            "canary",
            "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx=",
            "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!",
        ] {
            assert!(!opaque_token(invalid));
        }
    }

    #[test]
    fn grant_token_is_stable_and_bound_to_every_scope_field() {
        let fields = [
            "session",
            "organization",
            "environment",
            "port",
            "preview.test",
        ];
        let token = scoped_grant_token(
            "synthetic-key",
            fields[0],
            fields[1],
            fields[2],
            fields[3],
            fields[4],
        );
        assert!(opaque_token(&token));
        assert_eq!(
            token,
            scoped_grant_token(
                "synthetic-key",
                fields[0],
                fields[1],
                fields[2],
                fields[3],
                fields[4],
            )
        );
        for index in 0..fields.len() {
            let mut altered = fields;
            altered[index] = "other";
            assert_ne!(
                token,
                scoped_grant_token(
                    "synthetic-key",
                    altered[0],
                    altered[1],
                    altered[2],
                    altered[3],
                    altered[4],
                )
            );
        }
        assert_ne!(
            token,
            scoped_grant_token(
                "other-key",
                fields[0],
                fields[1],
                fields[2],
                fields[3],
                fields[4],
            )
        );
        assert_ne!(
            scoped_grant_token("key", "ab", "c", "e", "p", "h"),
            scoped_grant_token("key", "a", "bc", "e", "p", "h"),
        );
    }

    #[test]
    fn cookie_authority_rejects_duplicates_across_fields() {
        let mut headers = HeaderMap::new();
        headers.append(
            header::COOKIE,
            HeaderValue::from_static("app=x; __Host-codewire-preview=one"),
        );
        assert_eq!(unique_cookie(&headers, GRANT_COOKIE), Ok(Some("one")));
        headers.append(
            header::COOKIE,
            HeaderValue::from_static("__Host-codewire-preview=two"),
        );
        assert_eq!(unique_cookie(&headers, GRANT_COOKIE), Err(()));
        assert_eq!(unique_cookie(&headers, NONCE_COOKIE), Ok(None));
    }

    #[test]
    fn confirmation_is_bound_to_purpose_session_and_challenge() {
        let token = confirmation_token("synthetic-key", "session", "challenge");
        assert!(verify_confirmation(
            "synthetic-key",
            "session",
            "challenge",
            &token
        ));
        assert!(!verify_confirmation(
            "other-key",
            "session",
            "challenge",
            &token
        ));
        assert!(!verify_confirmation(
            "synthetic-key",
            "other-session",
            "challenge",
            &token
        ));
        assert!(!verify_confirmation(
            "synthetic-key",
            "session",
            "other-challenge",
            &token
        ));
        assert!(!verify_confirmation(
            "synthetic-key",
            "session",
            "challenge",
            ""
        ));
    }

    #[test]
    fn unsafe_cookie_requests_need_one_exact_origin() {
        let mut headers = HeaderMap::new();
        assert!(safe_cookie_request(
            &Method::GET,
            &headers,
            "https://preview.test"
        ));
        assert!(!safe_cookie_request(
            &Method::POST,
            &headers,
            "https://preview.test"
        ));
        headers.insert(
            header::ORIGIN,
            HeaderValue::from_static("https://preview.test"),
        );
        assert!(safe_cookie_request(
            &Method::POST,
            &headers,
            "https://preview.test"
        ));
        assert!(!safe_cookie_request(
            &Method::POST,
            &headers,
            "https://other.test"
        ));
        headers.append(
            header::ORIGIN,
            HeaderValue::from_static("https://preview.test"),
        );
        assert!(!safe_cookie_request(
            &Method::POST,
            &headers,
            "https://preview.test"
        ));
    }

    #[test]
    fn the_dashboard_origin_must_sit_outside_the_preview_domain() {
        assert_eq!(
            preview_frontend_origin("https://codewire.example/", "preview.example"),
            Ok("https://codewire.example".into())
        );
        for inside in [
            "https://preview.example/",
            "https://app.preview.example/",
            "https://APP.Preview.Example/",
        ] {
            assert!(
                preview_frontend_origin(inside, "preview.example").is_err(),
                "{inside}"
            );
        }
        assert!(preview_frontend_origin("https://codewire.example/", "").is_err());
    }

    #[test]
    fn frontend_must_be_an_exact_https_origin() {
        assert_eq!(
            frontend_origin("https://codewire.example/"),
            Ok("https://codewire.example".into())
        );
        for invalid in [
            "http://codewire.example",
            "https://user@codewire.example",
            "https://codewire.example/path",
            "https://codewire.example/?a=b",
            "https://codewire.example/#fragment",
        ] {
            assert!(frontend_origin(invalid).is_err());
        }
    }

    #[test]
    fn callback_return_never_leaves_the_preview_or_reenters_auth() {
        for valid in ["/", "/app", "/app?x=1&y=2"] {
            assert!(safe_return_path(valid));
        }
        for invalid in [
            "https://evil.test",
            "//evil.test",
            "/\\evil.test",
            "/app\r\n",
            "/app#fragment",
            "/.codewire/preview-auth/callback",
            "/app/../.codewire/preview-auth/callback",
            "/%2e/.codewire/preview-auth/callback",
        ] {
            assert!(!safe_return_path(invalid), "{invalid}");
        }
    }
}
