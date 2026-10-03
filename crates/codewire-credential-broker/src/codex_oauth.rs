//! Canonical protected material for a Codex ChatGPT OAuth identity.
//!
//! The import boundary accepts only the documented Codex `auth.json` shape
//! produced by an explicit, isolated login. It immediately normalizes that
//! provider-owned file into a small Codewire-owned envelope so later Codex
//! file-format changes do not silently alter the broker contract.

use base64::Engine as _;
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;
use zeroize::{Zeroize, Zeroizing};

const BUNDLE_VERSION: u32 = 1;
const MAX_BUNDLE_BYTES: usize = 1024 * 1024;
const MAX_TOKEN_BYTES: usize = 256 * 1024;
const MAX_ACCOUNT_ID_BYTES: usize = 1024;
const MAX_ACCOUNT_HINT_BYTES: usize = 256;
const MAX_JWT_PAYLOAD_BYTES: usize = 64 * 1024;
/// A proxied request refreshes an access token this close to its expiry.
pub(crate) const ACCESS_TOKEN_REFRESH_WINDOW_SECONDS: u64 = 5 * 60;
/// A delivered Codex login must stay valid this long, capped at half the
/// token's lifetime (see [`CodexOAuthCredential::should_refresh_within`]).
pub(crate) const CODEX_LOGIN_MINIMUM_VALIDITY_SECONDS: u64 = 30 * 60;
const FALLBACK_REFRESH_INTERVAL_SECONDS: u64 = 8 * 24 * 60 * 60;

/// Stable import failures that never retain provider material or parser input.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum CodexOAuthMaterialError {
    /// The source is not a supported ChatGPT OAuth login payload.
    #[error("Codex OAuth material is invalid or unsupported")]
    Invalid,
    /// The source or normalized material exceeds a fixed safety ceiling.
    #[error("Codex OAuth material exceeds the supported size")]
    TooLarge,
}

/// A normalized protected bundle ready to move into placement storage.
///
/// This type is deliberately non-cloneable, non-serializable, and has no
/// `Debug` implementation. Its allocation is zeroized on drop.
pub struct CanonicalCodexOAuthBundle(Zeroizing<Vec<u8>>);

impl CanonicalCodexOAuthBundle {
    /// Borrow the normalized bytes only while moving them into a protected
    /// placement store.
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_slice()
    }

    /// Consume the bundle and transfer its zeroizing byte allocation.
    pub fn into_bytes(mut self) -> Zeroizing<Vec<u8>> {
        Zeroizing::new(std::mem::take(&mut *self.0))
    }
}

/// Material plus safe display metadata produced by one explicit Codex login.
///
/// No token, protected-store reference, or provider response is exposed.
pub struct CodexOAuthImport {
    bundle: CanonicalCodexOAuthBundle,
    account_hint: Option<String>,
}

impl CodexOAuthImport {
    /// Non-secret account metadata suitable for credential inventory output.
    pub fn account_hint(&self) -> Option<&str> {
        self.account_hint.as_deref()
    }

    /// Consume the import into protected bytes and safe account metadata.
    pub fn into_parts(self) -> (CanonicalCodexOAuthBundle, Option<String>) {
        (self.bundle, self.account_hint)
    }
}

#[derive(Deserialize)]
struct CodexAuthFile {
    auth_mode: Option<String>,
    #[serde(rename = "OPENAI_API_KEY")]
    openai_api_key: Option<Zeroizing<String>>,
    tokens: Option<CodexAuthTokens>,
}

#[derive(Deserialize)]
struct CodexAuthTokens {
    id_token: Zeroizing<String>,
    access_token: Zeroizing<String>,
    refresh_token: Zeroizing<String>,
    account_id: Option<String>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CodexOAuthCredential {
    version: u32,
    access_token: Zeroizing<String>,
    refresh_token: Zeroizing<String>,
    id_token: Zeroizing<String>,
    account_id: String,
    fedramp: bool,
    refreshed_at_unix: u64,
}

impl CodexOAuthCredential {
    pub(crate) fn parse(material: &[u8]) -> Result<Self, CodexOAuthMaterialError> {
        if material.is_empty() || material.len() > MAX_BUNDLE_BYTES {
            return Err(if material.len() > MAX_BUNDLE_BYTES {
                CodexOAuthMaterialError::TooLarge
            } else {
                CodexOAuthMaterialError::Invalid
            });
        }
        let credential = serde_json::from_slice::<Self>(material)
            .map_err(|_| CodexOAuthMaterialError::Invalid)?;
        credential.validate()?;
        Ok(credential)
    }

    fn validate(&self) -> Result<(), CodexOAuthMaterialError> {
        if self.version != BUNDLE_VERSION
            || !valid_token(&self.access_token)
            || !valid_token(&self.refresh_token)
            || !valid_token(&self.id_token)
            || !valid_account_id(&self.account_id)
            || self.refreshed_at_unix == 0
        {
            return Err(CodexOAuthMaterialError::Invalid);
        }
        let claims = id_token_claims(&self.id_token)?;
        if claims.account_id.as_deref() != Some(self.account_id.as_str())
            || claims.fedramp != self.fedramp
        {
            return Err(CodexOAuthMaterialError::Invalid);
        }
        Ok(())
    }

    pub(crate) fn access_token(&self) -> &str {
        &self.access_token
    }

    pub(crate) fn id_token(&self) -> &str {
        &self.id_token
    }

    pub(crate) fn refresh_token(&self) -> &str {
        &self.refresh_token
    }

    pub(crate) fn account_id(&self) -> &str {
        &self.account_id
    }

    pub(crate) fn is_fedramp(&self) -> bool {
        self.fedramp
    }

    /// When this material was imported or last rotated: the same signal Codex
    /// CLI keeps as `last_refresh`. It is not an access-token expiry.
    pub(crate) fn refreshed_at_unix(&self) -> u64 {
        self.refreshed_at_unix
    }

    pub(crate) fn should_refresh(&self, now_unix: u64) -> bool {
        self.should_refresh_within(now_unix, ACCESS_TOKEN_REFRESH_WINDOW_SECONDS)
    }

    /// Whether the access token would expire within `minimum_validity_seconds`,
    /// capped at half its lifetime and never below the proxied request's
    /// five-minute window. The cap keeps a short-lived token from refreshing on
    /// every check: a token just obtained always satisfies its own minimum.
    /// The lifetime runs from the token's `iat`, or else from when Codewire
    /// last obtained it. Without an `exp`, only the fixed fallback interval
    /// applies, whatever the minimum.
    pub(crate) fn should_refresh_within(
        &self,
        now_unix: u64,
        minimum_validity_seconds: u64,
    ) -> bool {
        match jwt_validity(&self.access_token) {
            Ok(JwtValidity {
                expires_at: Some(expires_at),
                issued_at,
            }) => {
                let issued_at = issued_at.unwrap_or(self.refreshed_at_unix);
                let half_lifetime = expires_at.saturating_sub(issued_at) / 2;
                let window = minimum_validity_seconds
                    .min(half_lifetime)
                    .max(ACCESS_TOKEN_REFRESH_WINDOW_SECONDS);
                expires_at <= now_unix.saturating_add(window)
            }
            Ok(JwtValidity {
                expires_at: None, ..
            })
            | Err(_) => {
                self.refreshed_at_unix
                    .saturating_add(FALLBACK_REFRESH_INTERVAL_SECONDS)
                    <= now_unix
            }
        }
    }

    pub(crate) fn refreshed(
        mut self,
        id_token: Option<Zeroizing<String>>,
        access_token: Option<Zeroizing<String>>,
        refresh_token: Option<Zeroizing<String>>,
        refreshed_at_unix: u64,
    ) -> Result<Self, CodexOAuthMaterialError> {
        if let Some(id_token) = id_token {
            self.id_token = id_token;
        }
        if let Some(access_token) = access_token {
            self.access_token = access_token;
        }
        if let Some(refresh_token) = refresh_token {
            self.refresh_token = refresh_token;
        }
        self.refreshed_at_unix = refreshed_at_unix;
        self.validate()?;
        Ok(self)
    }

    pub(crate) fn to_bundle(&self) -> Result<CanonicalCodexOAuthBundle, CodexOAuthMaterialError> {
        let mut bytes = Zeroizing::new(
            serde_json::to_vec(&self).map_err(|_| CodexOAuthMaterialError::Invalid)?,
        );
        if bytes.len() > MAX_BUNDLE_BYTES {
            bytes.zeroize();
            return Err(CodexOAuthMaterialError::TooLarge);
        }
        Ok(CanonicalCodexOAuthBundle(bytes))
    }
}

#[derive(Default, Deserialize)]
struct JwtClaims {
    #[serde(default)]
    email: Option<String>,
    #[serde(rename = "https://api.openai.com/profile", default)]
    profile: Option<ProfileClaims>,
    #[serde(rename = "https://api.openai.com/auth", default)]
    auth: Option<AuthClaims>,
}

#[derive(Default, Deserialize)]
struct JwtExpirationClaims {
    #[serde(default)]
    exp: Option<u64>,
    #[serde(default)]
    iat: Option<u64>,
}

struct JwtValidity {
    expires_at: Option<u64>,
    issued_at: Option<u64>,
}

#[derive(Default, Deserialize)]
struct ProfileClaims {
    #[serde(default)]
    email: Option<String>,
}

#[derive(Default, Deserialize)]
struct AuthClaims {
    #[serde(default)]
    chatgpt_account_id: Option<String>,
    #[serde(default)]
    chatgpt_account_is_fedramp: bool,
}

struct ImportedClaims {
    account_id: Option<String>,
    account_hint: Option<String>,
    fedramp: bool,
}

/// Normalize the output of one isolated official Codex ChatGPT login.
///
/// Callers must not pass ambient `~/.codex/auth.json` here. The CLI owner of
/// this operation creates a private, empty login home and supplies only the
/// resulting bounded bytes.
pub fn import_codex_auth_json(source: &[u8]) -> Result<CodexOAuthImport, CodexOAuthMaterialError> {
    let imported_at_unix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| CodexOAuthMaterialError::Invalid)?
        .as_secs();
    import_codex_auth_json_at(source, imported_at_unix)
}

fn import_codex_auth_json_at(
    source: &[u8],
    imported_at_unix: u64,
) -> Result<CodexOAuthImport, CodexOAuthMaterialError> {
    if source.is_empty() || source.len() > MAX_BUNDLE_BYTES || imported_at_unix == 0 {
        return Err(if source.len() > MAX_BUNDLE_BYTES {
            CodexOAuthMaterialError::TooLarge
        } else {
            CodexOAuthMaterialError::Invalid
        });
    }
    let mut source = Zeroizing::new(source.to_vec());
    let parsed = serde_json::from_slice::<CodexAuthFile>(&source)
        .map_err(|_| CodexOAuthMaterialError::Invalid)?;
    source.zeroize();
    if parsed.auth_mode.as_deref() != Some("chatgpt") || parsed.openai_api_key.is_some() {
        return Err(CodexOAuthMaterialError::Invalid);
    }
    let tokens = parsed.tokens.ok_or(CodexOAuthMaterialError::Invalid)?;
    if !valid_token(&tokens.access_token)
        || !valid_token(&tokens.refresh_token)
        || !valid_token(&tokens.id_token)
    {
        return Err(CodexOAuthMaterialError::Invalid);
    }
    let claims = id_token_claims(&tokens.id_token)?;
    let account_id = tokens
        .account_id
        .or(claims.account_id)
        .filter(|value| valid_account_id(value))
        .ok_or(CodexOAuthMaterialError::Invalid)?;
    let account_hint = claims
        .account_hint
        .or_else(|| (account_id.len() <= MAX_ACCOUNT_HINT_BYTES).then(|| account_id.clone()));
    let credential = CodexOAuthCredential {
        version: BUNDLE_VERSION,
        access_token: tokens.access_token,
        refresh_token: tokens.refresh_token,
        id_token: tokens.id_token,
        account_id,
        fedramp: claims.fedramp,
        refreshed_at_unix: imported_at_unix,
    };
    credential.validate()?;
    Ok(CodexOAuthImport {
        bundle: credential.to_bundle()?,
        account_hint,
    })
}

fn valid_token(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_TOKEN_BYTES
        && value
            .bytes()
            .all(|byte| byte.is_ascii_graphic() && byte != b'"' && byte != b'\\')
}

fn valid_account_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_ACCOUNT_ID_BYTES
        && value.bytes().all(|byte| byte.is_ascii_graphic())
}

fn valid_account_hint(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_ACCOUNT_HINT_BYTES
        && value.trim() == value
        && value.chars().all(|character| !character.is_control())
}

fn id_token_claims(token: &str) -> Result<ImportedClaims, CodexOAuthMaterialError> {
    let claims = decode_jwt_payload::<JwtClaims>(token)?;
    let auth = claims.auth.unwrap_or_default();
    let account_hint = claims
        .email
        .or_else(|| claims.profile.and_then(|profile| profile.email))
        .filter(|value| valid_account_hint(value));
    Ok(ImportedClaims {
        account_id: auth.chatgpt_account_id,
        account_hint,
        fedramp: auth.chatgpt_account_is_fedramp,
    })
}

fn jwt_validity(token: &str) -> Result<JwtValidity, CodexOAuthMaterialError> {
    decode_jwt_payload::<JwtExpirationClaims>(token).map(|claims| JwtValidity {
        expires_at: claims.exp,
        issued_at: claims.iat,
    })
}

fn decode_jwt_payload<T>(token: &str) -> Result<T, CodexOAuthMaterialError>
where
    T: for<'de> Deserialize<'de>,
{
    let mut parts = token.split('.');
    let (Some(header), Some(payload), Some(signature), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(CodexOAuthMaterialError::Invalid);
    };
    if header.is_empty()
        || payload.is_empty()
        || signature.is_empty()
        || payload.len() > MAX_JWT_PAYLOAD_BYTES.saturating_mul(2)
    {
        return Err(CodexOAuthMaterialError::Invalid);
    }
    let mut decoded = Zeroizing::new(
        base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(payload)
            .map_err(|_| CodexOAuthMaterialError::Invalid)?,
    );
    if decoded.len() > MAX_JWT_PAYLOAD_BYTES {
        decoded.zeroize();
        return Err(CodexOAuthMaterialError::TooLarge);
    }
    let claims =
        serde_json::from_slice::<T>(&decoded).map_err(|_| CodexOAuthMaterialError::Invalid)?;
    decoded.zeroize();
    Ok(claims)
}

#[cfg(test)]
mod tests {
    use base64::Engine as _;
    use serde_json::json;

    use super::*;

    fn jwt(payload: serde_json::Value) -> String {
        let header = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(br#"{"alg":"none"}"#);
        let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(serde_json::to_vec(&payload).unwrap());
        format!("{header}.{payload}.synthetic-signature")
    }

    fn auth_json() -> Zeroizing<Vec<u8>> {
        Zeroizing::new(
            serde_json::to_vec(&json!({
                "auth_mode": "chatgpt",
                "OPENAI_API_KEY": null,
                "tokens": {
                    "id_token": jwt(json!({
                        "email": "developer@example.test",
                        "https://api.openai.com/auth": {
                            "chatgpt_account_id": "account-work",
                            "chatgpt_account_is_fedramp": false
                        }
                    })),
                    "access_token": "header.access.signature",
                    "refresh_token": "synthetic-refresh-token",
                    "account_id": "account-work"
                },
                "last_refresh": "2026-09-02T12:00:00Z"
            }))
            .unwrap(),
        )
    }

    #[test]
    fn normalizes_supported_chatgpt_auth_without_exposing_material_metadata() {
        let source = auth_json();
        let imported = import_codex_auth_json(&source).unwrap();
        assert_eq!(imported.account_hint(), Some("developer@example.test"));
        let (bundle, hint) = imported.into_parts();
        assert_eq!(hint.as_deref(), Some("developer@example.test"));
        let parsed = CodexOAuthCredential::parse(bundle.as_bytes()).unwrap();
        assert_eq!(parsed.access_token(), "header.access.signature");
        assert!(
            !bundle
                .as_bytes()
                .windows(13)
                .any(|part| part == b"OPENAI_API_KEY")
        );
    }

    #[test]
    fn rejects_api_keys_non_chatgpt_modes_and_mismatched_accounts() {
        for source in [
            json!({
                "auth_mode": "api_key",
                "OPENAI_API_KEY": "synthetic-key",
                "tokens": null
            }),
            json!({
                "auth_mode": "chatgpt",
                "OPENAI_API_KEY": null,
                "tokens": {
                    "id_token": jwt(json!({
                        "https://api.openai.com/auth": {
                            "chatgpt_account_id": "account-one"
                        }
                    })),
                    "access_token": "header.access.signature",
                    "refresh_token": "synthetic-refresh-token",
                    "account_id": "account-two"
                }
            }),
        ] {
            let bytes = Zeroizing::new(serde_json::to_vec(&source).unwrap());
            assert!(matches!(
                import_codex_auth_json(&bytes),
                Err(CodexOAuthMaterialError::Invalid)
            ));
        }
    }

    #[test]
    fn rejects_account_ids_that_cannot_be_forwarded_as_one_http_header() {
        for account_id in ["account work", "account-é"] {
            let source = Zeroizing::new(
                serde_json::to_vec(&json!({
                    "auth_mode": "chatgpt",
                    "OPENAI_API_KEY": null,
                    "tokens": {
                        "id_token": jwt(json!({
                            "https://api.openai.com/auth": {
                                "chatgpt_account_id": account_id
                            }
                        })),
                        "access_token": "header.access.signature",
                        "refresh_token": "synthetic-refresh-token",
                        "account_id": account_id
                    }
                }))
                .unwrap(),
            );
            assert!(matches!(
                import_codex_auth_json(&source),
                Err(CodexOAuthMaterialError::Invalid)
            ));
        }
    }

    #[test]
    fn canonical_parser_rejects_unknown_or_mutated_policy_fields() {
        let source = auth_json();
        let imported = import_codex_auth_json(&source).unwrap();
        let (bundle, _) = imported.into_parts();
        let mut value = serde_json::from_slice::<serde_json::Value>(bundle.as_bytes()).unwrap();
        value["destination"] = json!("https://evil.example");
        let bytes = Zeroizing::new(serde_json::to_vec(&value).unwrap());
        assert!(matches!(
            CodexOAuthCredential::parse(&bytes),
            Err(CodexOAuthMaterialError::Invalid)
        ));
    }

    #[test]
    fn errors_and_owned_types_do_not_format_provider_material() {
        assert_eq!(
            CodexOAuthMaterialError::Invalid.to_string(),
            "Codex OAuth material is invalid or unsupported"
        );
        assert_eq!(
            CodexOAuthMaterialError::TooLarge.to_string(),
            "Codex OAuth material exceeds the supported size"
        );
    }

    #[test]
    fn refresh_window_prefers_access_token_expiry_and_has_a_bounded_fallback() {
        let imported_at = 1_800_000_000;
        let access_token = jwt(json!({ "exp": imported_at + 600 }));
        let source = Zeroizing::new(
            serde_json::to_vec(&json!({
                "auth_mode": "chatgpt",
                "OPENAI_API_KEY": null,
                "tokens": {
                    "id_token": jwt(json!({
                        "https://api.openai.com/auth": {
                            "chatgpt_account_id": "account-work"
                        }
                    })),
                    "access_token": access_token,
                    "refresh_token": "synthetic-refresh-token",
                    "account_id": "account-work"
                }
            }))
            .unwrap(),
        );
        let imported = import_codex_auth_json_at(&source, imported_at).unwrap();
        let (bundle, _) = imported.into_parts();
        let credential = CodexOAuthCredential::parse(bundle.as_bytes()).unwrap();
        assert!(!credential.should_refresh(imported_at + 299));
        assert!(credential.should_refresh(imported_at + 300));

        let imported = import_codex_auth_json_at(&auth_json(), imported_at).unwrap();
        let (bundle, _) = imported.into_parts();
        let credential = CodexOAuthCredential::parse(bundle.as_bytes()).unwrap();
        assert!(!credential.should_refresh(imported_at + FALLBACK_REFRESH_INTERVAL_SECONDS - 1));
        assert!(credential.should_refresh(imported_at + FALLBACK_REFRESH_INTERVAL_SECONDS));
    }

    #[test]
    fn login_validity_minimum_is_capped_at_half_the_token_lifetime() {
        let credential = |access: serde_json::Value, refreshed_at: u64| {
            let source = Zeroizing::new(
                serde_json::to_vec(&json!({
                    "auth_mode": "chatgpt",
                    "OPENAI_API_KEY": null,
                    "tokens": {
                        "id_token": jwt(json!({
                            "https://api.openai.com/auth": {
                                "chatgpt_account_id": "account-work"
                            }
                        })),
                        "access_token": jwt(access),
                        "refresh_token": "synthetic-refresh-token",
                        "account_id": "account-work"
                    }
                }))
                .unwrap(),
            );
            let (bundle, _) = import_codex_auth_json_at(&source, refreshed_at)
                .unwrap()
                .into_parts();
            CodexOAuthCredential::parse(bundle.as_bytes()).unwrap()
        };
        let issued = 1_800_000_000;
        let minimum = CODEX_LOGIN_MINIMUM_VALIDITY_SECONDS;

        // A ten-day token: the full thirty minutes, versus five for a proxy.
        let long = credential(json!({ "iat": issued, "exp": issued + 864_000 }), issued);
        let expiry = issued + 864_000;
        assert!(!long.should_refresh_within(expiry - minimum - 1, minimum));
        assert!(long.should_refresh_within(expiry - minimum, minimum));
        assert!(!long.should_refresh(expiry - minimum));
        assert!(long.should_refresh(expiry - ACCESS_TOKEN_REFRESH_WINDOW_SECONDS));

        // A forty-minute token needs only twenty: a fresh one never refreshes.
        let short = credential(json!({ "iat": issued, "exp": issued + 2_400 }), issued);
        assert!(!short.should_refresh_within(issued, minimum));
        assert!(!short.should_refresh_within(issued + 1_199, minimum));
        assert!(short.should_refresh_within(issued + 1_200, minimum));

        // Without iat the lifetime runs from when Codewire obtained the token.
        let no_iat = credential(json!({ "exp": issued + 2_400 }), issued);
        assert!(!no_iat.should_refresh_within(issued + 1_199, minimum));
        assert!(no_iat.should_refresh_within(issued + 1_200, minimum));

        // A very short token keeps at least the proxy's five-minute window.
        let tiny = credential(json!({ "iat": issued, "exp": issued + 360 }), issued);
        assert!(!tiny.should_refresh_within(issued + 59, minimum));
        assert!(tiny.should_refresh_within(issued + 60, minimum));

        // Without exp, the minimum changes nothing: only the fallback applies.
        let opaque = credential(json!({ "iat": issued }), issued);
        assert!(
            !opaque.should_refresh_within(issued + FALLBACK_REFRESH_INTERVAL_SECONDS - 1, minimum)
        );
        assert!(opaque.should_refresh_within(issued + FALLBACK_REFRESH_INTERVAL_SECONDS, minimum));
    }

    #[test]
    fn refreshed_bundle_preserves_missing_fields_and_rejects_account_changes() {
        let imported = import_codex_auth_json_at(&auth_json(), 1_800_000_000).unwrap();
        let (bundle, _) = imported.into_parts();
        let credential = CodexOAuthCredential::parse(bundle.as_bytes()).unwrap();
        let refreshed = credential
            .refreshed(
                None,
                Some(Zeroizing::new("new.access.token".to_owned())),
                None,
                1_800_000_100,
            )
            .unwrap();
        assert_eq!(refreshed.access_token(), "new.access.token");
        assert_eq!(refreshed.refresh_token(), "synthetic-refresh-token");
        assert_eq!(refreshed.account_id(), "account-work");

        let changed_account = refreshed.refreshed(
            Some(Zeroizing::new(jwt(json!({
                "https://api.openai.com/auth": {
                    "chatgpt_account_id": "different-account"
                }
            })))),
            None,
            None,
            1_800_000_200,
        );
        assert!(matches!(
            changed_account,
            Err(CodexOAuthMaterialError::Invalid)
        ));
    }
}
