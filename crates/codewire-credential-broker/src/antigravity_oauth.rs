//! Canonical protected material for an Antigravity Google OAuth sign-in
//! (#6555).
//!
//! The import boundary accepts only the tokens of a completed Antigravity
//! Google sign-in, enforces the exact granted-scope allow-list on enrollment
//! and every refresh, extracts `id_token_email` only after checking `iss` and
//! `aud` (never storing the signed `id_token`), and normalizes into a small
//! Codewire-owned zeroizing envelope.

use base64::Engine as _;
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;
use zeroize::{Zeroize, Zeroizing};

pub(crate) use crate::codex_oauth::ACCESS_TOKEN_REFRESH_WINDOW_SECONDS;
use crate::provider_oauth::antigravity::ANTIGRAVITY_OAUTH_CLIENT_ID;

const BUNDLE_VERSION: u32 = 1;
const MAX_BUNDLE_BYTES: usize = 64 * 1024;
const MAX_TOKEN_BYTES: usize = 16 * 1024;
const MAX_ID_TOKEN_BYTES: usize = 64 * 1024;
const MAX_SCOPES: usize = 16;
const MAX_SCOPE_BYTES: usize = 128;
const MAX_ACCOUNT_HINT_BYTES: usize = 256;
const MIN_ACCESS_TOKEN_LIFETIME_SECONDS: u64 = 60;
const MAX_ACCESS_TOKEN_LIFETIME_SECONDS: u64 = 31 * 24 * 60 * 60;

/// Exact scopes requested by Antigravity 1.5.17.
///
/// Both enrollment and every refresh fail closed if Google grants any scope
/// outside this closed set (#6555).
pub const ANTIGRAVITY_ALLOWED_SCOPES: [&str; 6] = [
    "https://www.googleapis.com/auth/cloud-platform",
    "https://www.googleapis.com/auth/userinfo.email",
    "https://www.googleapis.com/auth/userinfo.profile",
    "https://www.googleapis.com/auth/cclog",
    "https://www.googleapis.com/auth/experimentsandconfigs",
    "openid",
];

/// Minimum scope required for Antigravity Cloud Code inference.
pub const ANTIGRAVITY_REQUIRED_SCOPES: [&str; 1] =
    ["https://www.googleapis.com/auth/cloud-platform"];

/// Stable failures that never retain provider material or parser input.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum AntigravityOAuthMaterialError {
    /// The source is not a supported Antigravity Google sign-in.
    #[error("Antigravity sign-in material is invalid or unsupported")]
    Invalid,
    /// The source or normalized material exceeds a fixed safety ceiling.
    #[error("Antigravity sign-in material exceeds the supported size")]
    TooLarge,
}

/// A normalized protected bundle ready to move into placement storage.
///
/// Deliberately non-cloneable, non-serializable, and without `Debug`. Its
/// allocation is zeroized on drop.
pub struct CanonicalAntigravityOAuthBundle(Zeroizing<Vec<u8>>);

impl CanonicalAntigravityOAuthBundle {
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_slice()
    }

    pub fn into_bytes(mut self) -> Zeroizing<Vec<u8>> {
        Zeroizing::new(std::mem::take(&mut *self.0))
    }
}

/// Material plus safe display metadata produced by one completed sign-in.
/// No token, protected-store reference, or signed `id_token` is exposed.
pub struct AntigravityOAuthImport {
    bundle: CanonicalAntigravityOAuthBundle,
    account_hint: Option<String>,
}

impl AntigravityOAuthImport {
    pub fn account_hint(&self) -> Option<&str> {
        self.account_hint.as_deref()
    }

    pub fn into_parts(self) -> (CanonicalAntigravityOAuthBundle, Option<String>) {
        (self.bundle, self.account_hint)
    }
}

/// Token fields returned by `POST https://oauth2.googleapis.com/token`.
pub struct AntigravityIssuedTokens {
    pub access_token: Zeroizing<String>,
    pub refresh_token: Option<Zeroizing<String>>,
    pub id_token: Option<Zeroizing<String>>,
    pub expires_in: u64,
    pub scope: Option<String>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AntigravityOAuthCredential {
    version: u32,
    access_token: Zeroizing<String>,
    refresh_token: Zeroizing<String>,
    expires_at_unix: u64,
    scopes: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    account_hint: Option<String>,
    refreshed_at_unix: u64,
}

impl AntigravityOAuthCredential {
    pub(crate) fn parse(material: &[u8]) -> Result<Self, AntigravityOAuthMaterialError> {
        if material.is_empty() || material.len() > MAX_BUNDLE_BYTES {
            return Err(if material.len() > MAX_BUNDLE_BYTES {
                AntigravityOAuthMaterialError::TooLarge
            } else {
                AntigravityOAuthMaterialError::Invalid
            });
        }
        let credential = serde_json::from_slice::<Self>(material)
            .map_err(|_| AntigravityOAuthMaterialError::Invalid)?;
        credential.validate()?;
        Ok(credential)
    }

    pub(crate) fn access_token(&self) -> &str {
        &self.access_token
    }

    pub(crate) fn refresh_token(&self) -> &str {
        &self.refresh_token
    }

    pub(crate) fn account_hint(&self) -> Option<&str> {
        self.account_hint.as_deref()
    }

    pub(crate) fn scopes(&self) -> &[String] {
        &self.scopes
    }

    pub(crate) fn refreshed_at_unix(&self) -> u64 {
        self.refreshed_at_unix
    }

    pub(crate) fn should_refresh(&self, now_unix: u64) -> bool {
        self.should_refresh_within(now_unix, ACCESS_TOKEN_REFRESH_WINDOW_SECONDS)
    }

    pub(crate) fn should_refresh_within(
        &self,
        now_unix: u64,
        minimum_validity_seconds: u64,
    ) -> bool {
        let lifetime = self.expires_at_unix.saturating_sub(self.refreshed_at_unix);
        let window = minimum_validity_seconds.min(lifetime / 2);
        now_unix.saturating_add(window) >= self.expires_at_unix
    }

    pub(crate) fn has_expired(&self, now_unix: u64) -> bool {
        now_unix >= self.expires_at_unix
    }

    /// Apply a rotated token response from `POST https://oauth2.googleapis.com/token`.
    /// Google may omit `refresh_token` on refresh; when omitted, the existing
    /// refresh token is retained. Granted scopes (if reported) must stay within
    /// [`ANTIGRAVITY_ALLOWED_SCOPES`].
    pub(crate) fn refreshed(
        self,
        tokens: AntigravityIssuedTokens,
        refreshed_at_unix: u64,
    ) -> Result<Self, AntigravityOAuthMaterialError> {
        validate_lifetime(tokens.expires_in)?;
        validate_token(&tokens.access_token)?;
        let refresh_token = match tokens.refresh_token {
            Some(next) => {
                validate_token(&next)?;
                next
            }
            None => self.refresh_token,
        };
        let scopes = match tokens.scope {
            Some(scope) => parse_and_validate_scopes(&scope)?,
            None => self.scopes,
        };
        let account_hint = match tokens.id_token {
            Some(id_token) => extract_id_token_email(&id_token)?.or(self.account_hint),
            None => self.account_hint,
        };
        let next = Self {
            version: BUNDLE_VERSION,
            access_token: tokens.access_token,
            refresh_token,
            expires_at_unix: refreshed_at_unix
                .checked_add(tokens.expires_in)
                .ok_or(AntigravityOAuthMaterialError::Invalid)?,
            scopes,
            account_hint,
            refreshed_at_unix,
        };
        next.validate()?;
        Ok(next)
    }

    pub(crate) fn to_bundle(
        &self,
    ) -> Result<CanonicalAntigravityOAuthBundle, AntigravityOAuthMaterialError> {
        self.validate()?;
        let bytes = Zeroizing::new(
            serde_json::to_vec(self).map_err(|_| AntigravityOAuthMaterialError::Invalid)?,
        );
        if bytes.len() > MAX_BUNDLE_BYTES {
            return Err(AntigravityOAuthMaterialError::TooLarge);
        }
        Ok(CanonicalAntigravityOAuthBundle(bytes))
    }

    fn validate(&self) -> Result<(), AntigravityOAuthMaterialError> {
        if self.version != BUNDLE_VERSION
            || self.refreshed_at_unix == 0
            || self.expires_at_unix <= self.refreshed_at_unix
        {
            return Err(AntigravityOAuthMaterialError::Invalid);
        }
        validate_token(&self.access_token)?;
        validate_token(&self.refresh_token)?;
        validate_scope_list(&self.scopes)?;
        if let Some(hint) = &self.account_hint {
            validate_account_hint(hint)?;
        }
        Ok(())
    }
}

/// Normalize one completed Antigravity Google OAuth enrollment into a
/// canonical protected bundle plus non-secret `account_hint` email.
pub fn import_antigravity_tokens(
    tokens: AntigravityIssuedTokens,
) -> Result<AntigravityOAuthImport, AntigravityOAuthMaterialError> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| AntigravityOAuthMaterialError::Invalid)?
        .as_secs();
    import_antigravity_tokens_at(tokens, now)
}

pub(crate) fn import_antigravity_tokens_at(
    tokens: AntigravityIssuedTokens,
    now_unix: u64,
) -> Result<AntigravityOAuthImport, AntigravityOAuthMaterialError> {
    if now_unix == 0 {
        return Err(AntigravityOAuthMaterialError::Invalid);
    }
    validate_lifetime(tokens.expires_in)?;
    validate_token(&tokens.access_token)?;
    let refresh_token = tokens
        .refresh_token
        .ok_or(AntigravityOAuthMaterialError::Invalid)?;
    validate_token(&refresh_token)?;
    let scope_text = tokens.scope.ok_or(AntigravityOAuthMaterialError::Invalid)?;
    let scopes = parse_and_validate_scopes(&scope_text)?;
    let account_hint = match tokens.id_token {
        Some(id_token) => extract_id_token_email(&id_token)?,
        None => None,
    };
    let credential = AntigravityOAuthCredential {
        version: BUNDLE_VERSION,
        access_token: tokens.access_token,
        refresh_token,
        expires_at_unix: now_unix
            .checked_add(tokens.expires_in)
            .ok_or(AntigravityOAuthMaterialError::Invalid)?,
        scopes,
        account_hint: account_hint.clone(),
        refreshed_at_unix: now_unix,
    };
    let bundle = credential.to_bundle()?;
    Ok(AntigravityOAuthImport {
        bundle,
        account_hint,
    })
}

fn validate_lifetime(expires_in: u64) -> Result<(), AntigravityOAuthMaterialError> {
    if !(MIN_ACCESS_TOKEN_LIFETIME_SECONDS..=MAX_ACCESS_TOKEN_LIFETIME_SECONDS)
        .contains(&expires_in)
    {
        return Err(AntigravityOAuthMaterialError::Invalid);
    }
    Ok(())
}

fn validate_token(token: &str) -> Result<(), AntigravityOAuthMaterialError> {
    if token.is_empty() {
        return Err(AntigravityOAuthMaterialError::Invalid);
    }
    if token.len() > MAX_TOKEN_BYTES {
        return Err(AntigravityOAuthMaterialError::TooLarge);
    }
    if !token.bytes().all(|byte| byte.is_ascii_graphic()) {
        return Err(AntigravityOAuthMaterialError::Invalid);
    }
    Ok(())
}

fn parse_and_validate_scopes(raw: &str) -> Result<Vec<String>, AntigravityOAuthMaterialError> {
    let mut scopes: Vec<String> = raw
        .split_ascii_whitespace()
        .filter(|item| !item.is_empty())
        .map(str::to_owned)
        .collect();
    scopes.sort();
    scopes.dedup();
    validate_scope_list(&scopes)?;
    Ok(scopes)
}

pub(crate) fn within_antigravity_scopes(scopes: &[String]) -> bool {
    validate_scope_list(scopes).is_ok()
}

fn validate_scope_list(scopes: &[String]) -> Result<(), AntigravityOAuthMaterialError> {
    if scopes.is_empty() || scopes.len() > MAX_SCOPES {
        return Err(AntigravityOAuthMaterialError::Invalid);
    }
    for scope in scopes {
        if scope.is_empty()
            || scope.len() > MAX_SCOPE_BYTES
            || !ANTIGRAVITY_ALLOWED_SCOPES.contains(&scope.as_str())
        {
            return Err(AntigravityOAuthMaterialError::Invalid);
        }
    }
    for required in ANTIGRAVITY_REQUIRED_SCOPES {
        if !scopes.iter().any(|scope| scope == required) {
            return Err(AntigravityOAuthMaterialError::Invalid);
        }
    }
    Ok(())
}

/// Must match `codewire_workload_secrets::AntigravityLogin::validate` so any
/// stored `account_hint` can be sealed into an `AntigravityLogin` without
/// failing delivery.
pub(crate) fn is_valid_account_hint(hint: &str) -> bool {
    !hint.is_empty()
        && hint.len() <= MAX_ACCOUNT_HINT_BYTES
        && hint
            .bytes()
            .all(|byte| byte.is_ascii_graphic() && byte != b'"' && byte != b'\\')
}

fn validate_account_hint(hint: &str) -> Result<(), AntigravityOAuthMaterialError> {
    if !is_valid_account_hint(hint) {
        return Err(AntigravityOAuthMaterialError::Invalid);
    }
    Ok(())
}

#[derive(Deserialize)]
struct IdTokenClaims {
    iss: String,
    aud: String,
    #[serde(default)]
    email: Option<String>,
}

/// Extract non-secret `email` from a Google `id_token` received directly over
/// TLS from `https://oauth2.googleapis.com/token`, after checking `iss` and
/// `aud` match Google and [`ANTIGRAVITY_OAUTH_CLIENT_ID`] (#6555). The signed
/// `id_token` itself is never stored.
fn extract_id_token_email(id_token: &str) -> Result<Option<String>, AntigravityOAuthMaterialError> {
    if id_token.is_empty() {
        return Ok(None);
    }
    if id_token.len() > MAX_ID_TOKEN_BYTES {
        return Err(AntigravityOAuthMaterialError::TooLarge);
    }
    let mut parts = id_token.split('.');
    let (Some(header), Some(payload), Some(sig), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(AntigravityOAuthMaterialError::Invalid);
    };
    if header.is_empty() || payload.is_empty() || sig.is_empty() {
        return Err(AntigravityOAuthMaterialError::Invalid);
    }
    let mut decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload)
        .map_err(|_| AntigravityOAuthMaterialError::Invalid)?;
    let claims = serde_json::from_slice::<IdTokenClaims>(&decoded);
    decoded.zeroize();
    let claims = claims.map_err(|_| AntigravityOAuthMaterialError::Invalid)?;
    if !matches!(
        claims.iss.as_str(),
        "https://accounts.google.com" | "accounts.google.com"
    ) || claims.aud != ANTIGRAVITY_OAUTH_CLIENT_ID
    {
        return Err(AntigravityOAuthMaterialError::Invalid);
    }
    let Some(email) = claims.email.filter(|value| !value.is_empty()) else {
        return Ok(None);
    };
    if email.len() > MAX_ACCOUNT_HINT_BYTES {
        return Err(AntigravityOAuthMaterialError::Invalid);
    }
    if !is_valid_account_hint(&email) {
        return Ok(None);
    }
    Ok(Some(email))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fake_id_token(iss: &str, aud: &str, email: Option<&str>) -> Zeroizing<String> {
        let header = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(br#"{"alg":"RS256"}"#);
        let payload = serde_json::json!({
            "iss": iss,
            "aud": aud,
            "email": email,
        });
        let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(serde_json::to_vec(&payload).unwrap());
        Zeroizing::new(format!("{header}.{payload}.synthetic-sig"))
    }

    fn base_tokens() -> AntigravityIssuedTokens {
        AntigravityIssuedTokens {
            access_token: Zeroizing::new("synthetic-access-token".into()),
            refresh_token: Some(Zeroizing::new("synthetic-refresh-token".into())),
            id_token: Some(fake_id_token(
                "https://accounts.google.com",
                ANTIGRAVITY_OAUTH_CLIENT_ID,
                Some("user@example.test"),
            )),
            expires_in: 3600,
            scope: Some(ANTIGRAVITY_ALLOWED_SCOPES.join(" ")),
        }
    }

    #[test]
    fn import_round_trips_and_never_stores_id_token() {
        let imported = import_antigravity_tokens_at(base_tokens(), 1_800_000_000).unwrap();
        assert_eq!(imported.account_hint(), Some("user@example.test"));
        let (bundle, _) = imported.into_parts();
        let text = std::str::from_utf8(bundle.as_bytes()).unwrap();
        assert!(
            !text.contains("synthetic-sig"),
            "signed id_token must never be stored"
        );
        let parsed = AntigravityOAuthCredential::parse(bundle.as_bytes()).unwrap();
        assert_eq!(parsed.access_token(), "synthetic-access-token");
        assert_eq!(parsed.refresh_token(), "synthetic-refresh-token");
        assert_eq!(parsed.account_hint(), Some("user@example.test"));
        assert!(!parsed.has_expired(1_800_000_100));
        assert!(parsed.should_refresh_within(1_800_003_350, ACCESS_TOKEN_REFRESH_WINDOW_SECONDS));
        assert!(parsed.has_expired(1_800_003_600));
    }

    #[test]
    fn extra_or_missing_required_scope_is_refused_on_import_and_refresh() {
        let mut extra = base_tokens();
        extra.scope = Some(format!(
            "{} https://www.googleapis.com/auth/drive",
            ANTIGRAVITY_ALLOWED_SCOPES.join(" ")
        ));
        assert!(import_antigravity_tokens_at(extra, 1_800_000_000).is_err());

        let mut missing = base_tokens();
        missing.scope = Some("openid https://www.googleapis.com/auth/userinfo.email".into());
        assert!(import_antigravity_tokens_at(missing, 1_800_000_000).is_err());

        let (bundle, _) = import_antigravity_tokens_at(base_tokens(), 1_800_000_000)
            .unwrap()
            .into_parts();
        let parsed = AntigravityOAuthCredential::parse(bundle.as_bytes()).unwrap();
        let mut bad_refresh = base_tokens();
        bad_refresh.scope = Some(format!(
            "{} https://www.googleapis.com/auth/gmail.readonly",
            ANTIGRAVITY_ALLOWED_SCOPES.join(" ")
        ));
        assert!(parsed.refreshed(bad_refresh, 1_800_003_500).is_err());
    }

    #[test]
    fn id_token_checks_iss_aud_and_email_length() {
        let mut wrong_iss = base_tokens();
        wrong_iss.id_token = Some(fake_id_token(
            "https://evil.example",
            ANTIGRAVITY_OAUTH_CLIENT_ID,
            Some("user@example.test"),
        ));
        assert!(import_antigravity_tokens_at(wrong_iss, 1_800_000_000).is_err());

        let mut wrong_aud = base_tokens();
        wrong_aud.id_token = Some(fake_id_token(
            "https://accounts.google.com",
            "other-client.apps.googleusercontent.com",
            Some("user@example.test"),
        ));
        assert!(import_antigravity_tokens_at(wrong_aud, 1_800_000_000).is_err());

        let mut huge_email = base_tokens();
        huge_email.id_token = Some(fake_id_token(
            "https://accounts.google.com",
            ANTIGRAVITY_OAUTH_CLIENT_ID,
            Some(&"a".repeat(MAX_ACCOUNT_HINT_BYTES + 1)),
        ));
        assert!(import_antigravity_tokens_at(huge_email, 1_800_000_000).is_err());

        // Non-ASCII / space / quote / backslash hints are dropped on import and
        // refused in stored bundles, maintaining exact parity with AntigravityLogin::validate.
        for bad_hint in [
            "u ser@example.test",
            "u\"ser@example.test",
            "u\\ser@example.test",
            "üser@example.test",
        ] {
            assert!(!is_valid_account_hint(bad_hint), "{bad_hint}");
            let mut non_ascii = base_tokens();
            non_ascii.id_token = Some(fake_id_token(
                "https://accounts.google.com",
                ANTIGRAVITY_OAUTH_CLIENT_ID,
                Some(bad_hint),
            ));
            let (_, hint) = import_antigravity_tokens_at(non_ascii, 1_800_000_000)
                .unwrap()
                .into_parts();
            assert_eq!(hint, None, "{bad_hint}");
        }
        assert!(is_valid_account_hint("user+tag@example.test"));
    }
}
