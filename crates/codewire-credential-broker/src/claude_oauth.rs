//! Canonical protected material for a Claude sign-in: Claude Code's own
//! claude.ai OAuth login, enrolled and refreshed by Codewire.
//!
//! The import boundary accepts only the tokens of a completed sign-in and the
//! plan read from Claude's OAuth profile, and immediately normalizes them into
//! a small Codewire-owned envelope. The plan, rate-limit tier and granted
//! scopes are not secret; they live in the envelope because the access token
//! needs them wherever it is used, and they change only at enrollment or on a
//! refresh that reports new scopes.

use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;
use zeroize::{Zeroize, Zeroizing};

pub(crate) use crate::codex_oauth::ACCESS_TOKEN_REFRESH_WINDOW_SECONDS;

const BUNDLE_VERSION: u32 = 1;
const MAX_BUNDLE_BYTES: usize = 64 * 1024;
const MAX_TOKEN_BYTES: usize = 16 * 1024;
const MAX_SCOPES: usize = 32;
const MAX_SCOPE_BYTES: usize = 128;
const MAX_RATE_LIMIT_TIER_BYTES: usize = 128;
const MAX_ACCOUNT_HINT_BYTES: usize = 256;
/// The shortest and longest access-token lifetimes Codewire accepts from the
/// provider. Claude issues tokens for about eight hours.
const MIN_ACCESS_TOKEN_LIFETIME_SECONDS: u64 = 60;
const MAX_ACCESS_TOKEN_LIFETIME_SECONDS: u64 = 31 * 24 * 60 * 60;
/// A refresh-token lifetime the provider reports is accepted up to this.
const MAX_REFRESH_TOKEN_LIFETIME_SECONDS: u64 = 10 * 365 * 24 * 60 * 60;
/// The scopes a Claude sign-in must keep: inference for every turn, and the
/// profile for Claude Code's `/usage` and plan. A refresh that drops either is
/// refused rather than stored.
pub(crate) const REQUIRED_SCOPES: [&str; 2] = ["user:inference", "user:profile"];
/// Scopes a stored Claude sign-in never carries: `org:create_api_key` mints
/// lasting API keys, and Claude Code itself accepts a login that has it, so a
/// sign-in or refresh granting it is refused here, outside the environment,
/// rather than stored. Delivery separately admits only the sign-in scopes.
const FORBIDDEN_SCOPES: [&str; 1] = ["org:create_api_key"];
/// A delivered Claude login keeps at least this long (capped at half its
/// lifetime): Claude Code itself refreshes only within five minutes of
/// `expiresAt`, so while delivery works it never tries the placeholder.
pub(crate) const CLAUDE_LOGIN_MINIMUM_VALIDITY_SECONDS: u64 = 30 * 60;

/// Stable failures that never retain provider material or parser input.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum ClaudeOAuthMaterialError {
    /// The source is not a supported Claude sign-in.
    #[error("Claude sign-in material is invalid or unsupported")]
    Invalid,
    /// The source or normalized material exceeds a fixed safety ceiling.
    #[error("Claude sign-in material exceeds the supported size")]
    TooLarge,
}

/// A normalized protected bundle ready to move into placement storage.
///
/// Deliberately non-cloneable, non-serializable and without `Debug`. Its
/// allocation is zeroized on drop.
pub struct CanonicalClaudeOAuthBundle(Zeroizing<Vec<u8>>);

impl CanonicalClaudeOAuthBundle {
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

/// Material plus safe display metadata produced by one completed sign-in.
/// No token, protected-store reference or provider response is exposed.
pub struct ClaudeOAuthImport {
    bundle: CanonicalClaudeOAuthBundle,
    account_hint: Option<String>,
}

impl ClaudeOAuthImport {
    /// The account's email from Claude's OAuth profile, when it has one.
    pub fn account_hint(&self) -> Option<&str> {
        self.account_hint.as_deref()
    }

    /// Consume the import into protected bytes and safe account metadata.
    pub fn into_parts(self) -> (CanonicalClaudeOAuthBundle, Option<String>) {
        (self.bundle, self.account_hint)
    }
}

/// Claude's plan for the signed-in organization, as Claude Code names it in
/// its own login: `max`, `pro`, `team` or `enterprise`.
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ClaudeSubscriptionType {
    Max,
    Pro,
    Team,
    Enterprise,
}

impl ClaudeSubscriptionType {
    /// Claude Code's mapping from the profile's `organization_type`. Any other
    /// organization type has no plan label.
    pub fn from_organization_type(value: &str) -> Option<Self> {
        match value {
            "claude_max" => Some(Self::Max),
            "claude_pro" => Some(Self::Pro),
            "claude_team" => Some(Self::Team),
            "claude_enterprise" => Some(Self::Enterprise),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Max => "max",
            Self::Pro => "pro",
            Self::Team => "team",
            Self::Enterprise => "enterprise",
        }
    }
}

/// The plan read from Claude's OAuth profile at sign-in. Not secret.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ClaudeProfile {
    pub email: Option<String>,
    pub subscription_type: Option<ClaudeSubscriptionType>,
    pub rate_limit_tier: Option<String>,
}

/// The token endpoint's answer to a sign-in or a refresh, before
/// normalization. Lifetimes are in seconds, as the provider sends them.
pub struct ClaudeIssuedTokens {
    pub access_token: Zeroizing<String>,
    /// Absent on a refresh that keeps the previous refresh token.
    pub refresh_token: Option<Zeroizing<String>>,
    pub expires_in: u64,
    pub refresh_token_expires_in: Option<u64>,
    /// Space-separated, as the provider sends it. Absent means unchanged.
    pub scope: Option<String>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ClaudeOAuthCredential {
    version: u32,
    access_token: Zeroizing<String>,
    refresh_token: Zeroizing<String>,
    expires_at_unix: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    refresh_expires_at_unix: Option<u64>,
    scopes: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    subscription_type: Option<ClaudeSubscriptionType>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    rate_limit_tier: Option<String>,
    refreshed_at_unix: u64,
}

impl ClaudeOAuthCredential {
    pub(crate) fn parse(material: &[u8]) -> Result<Self, ClaudeOAuthMaterialError> {
        if material.len() > MAX_BUNDLE_BYTES {
            return Err(ClaudeOAuthMaterialError::TooLarge);
        }
        if material.is_empty() {
            return Err(ClaudeOAuthMaterialError::Invalid);
        }
        let credential = serde_json::from_slice::<Self>(material)
            .map_err(|_| ClaudeOAuthMaterialError::Invalid)?;
        credential.validate()?;
        Ok(credential)
    }

    fn validate(&self) -> Result<(), ClaudeOAuthMaterialError> {
        if self.version != BUNDLE_VERSION
            || !valid_token(&self.access_token)
            || !valid_token(&self.refresh_token)
            || self.expires_at_unix == 0
            || self.refreshed_at_unix == 0
            || self
                .refresh_expires_at_unix
                .is_some_and(|expiry| expiry <= self.refreshed_at_unix)
            || !valid_scopes(&self.scopes)
            || !self
                .rate_limit_tier
                .as_deref()
                .is_none_or(valid_rate_limit_tier)
        {
            return Err(ClaudeOAuthMaterialError::Invalid);
        }
        Ok(())
    }

    pub(crate) fn access_token(&self) -> &str {
        &self.access_token
    }

    pub(crate) fn refresh_token(&self) -> &str {
        &self.refresh_token
    }

    /// When the access token expires, as the provider reported its lifetime.
    pub(crate) fn expires_at_unix(&self) -> u64 {
        self.expires_at_unix
    }

    /// When the refresh token expires, when the provider said.
    #[cfg(any(test, feature = "platform"))]
    pub(crate) fn refresh_expires_at_unix(&self) -> Option<u64> {
        self.refresh_expires_at_unix
    }

    /// The scopes exactly as granted.
    pub(crate) fn scopes(&self) -> &[String] {
        &self.scopes
    }

    pub(crate) fn subscription_type(&self) -> Option<ClaudeSubscriptionType> {
        self.subscription_type
    }

    pub(crate) fn rate_limit_tier(&self) -> Option<&str> {
        self.rate_limit_tier.as_deref()
    }

    /// When this material was imported or last rotated.
    pub(crate) fn refreshed_at_unix(&self) -> u64 {
        self.refreshed_at_unix
    }

    /// A proxied request refreshes within Claude Code's own five minutes of
    /// expiry.
    pub(crate) fn should_refresh(&self, now_unix: u64) -> bool {
        self.should_refresh_within(now_unix, ACCESS_TOKEN_REFRESH_WINDOW_SECONDS)
    }

    /// Whether the access token would expire within `minimum_validity_seconds`,
    /// capped at half its lifetime (from when Codewire obtained it) and never
    /// below the proxied request's five-minute window. The cap keeps a
    /// short-lived token from refreshing on every check.
    pub(crate) fn should_refresh_within(
        &self,
        now_unix: u64,
        minimum_validity_seconds: u64,
    ) -> bool {
        let half_lifetime = self.expires_at_unix.saturating_sub(self.refreshed_at_unix) / 2;
        let window = minimum_validity_seconds
            .min(half_lifetime)
            .max(ACCESS_TOKEN_REFRESH_WINDOW_SECONDS);
        self.expires_at_unix <= now_unix.saturating_add(window)
    }

    /// Apply one refresh answer. A missing refresh token keeps the previous
    /// one, as Claude Code does; missing scopes mean unchanged (RFC 6749
    /// section 5.1). The rotated login must keep the required scopes, and its
    /// lifetimes must be in range. The plan is kept: it is read from the
    /// profile only at sign-in and reconnect.
    pub(crate) fn refreshed(
        mut self,
        tokens: ClaudeIssuedTokens,
        refreshed_at_unix: u64,
    ) -> Result<Self, ClaudeOAuthMaterialError> {
        let ClaudeIssuedTokens {
            access_token,
            refresh_token,
            expires_in,
            refresh_token_expires_in,
            scope,
        } = tokens;
        let rotated = refresh_token.is_some();
        self.access_token = access_token;
        if let Some(refresh_token) = refresh_token {
            self.refresh_token = refresh_token;
        }
        self.expires_at_unix = access_token_expiry(refreshed_at_unix, expires_in)?;
        self.refresh_expires_at_unix =
            match refresh_token_expiry(refreshed_at_unix, refresh_token_expires_in)? {
                Some(expiry) => Some(expiry),
                // An unchanged refresh token keeps its known expiry.
                None if !rotated => self.refresh_expires_at_unix,
                None => None,
            };
        if let Some(scope) = scope {
            self.scopes = parse_scopes(&scope)?;
        }
        self.refreshed_at_unix = refreshed_at_unix;
        self.validate()?;
        Ok(self)
    }

    pub(crate) fn to_bundle(&self) -> Result<CanonicalClaudeOAuthBundle, ClaudeOAuthMaterialError> {
        let mut bytes = Zeroizing::new(
            serde_json::to_vec(&self).map_err(|_| ClaudeOAuthMaterialError::Invalid)?,
        );
        if bytes.len() > MAX_BUNDLE_BYTES {
            bytes.zeroize();
            return Err(ClaudeOAuthMaterialError::TooLarge);
        }
        Ok(CanonicalClaudeOAuthBundle(bytes))
    }
}

/// Normalize the tokens of one completed Claude sign-in and the profile read
/// with them. The email becomes the account hint; it is not secret.
pub fn import_claude_tokens(
    tokens: ClaudeIssuedTokens,
    profile: ClaudeProfile,
) -> Result<ClaudeOAuthImport, ClaudeOAuthMaterialError> {
    let imported_at_unix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| ClaudeOAuthMaterialError::Invalid)?
        .as_secs();
    import_tokens_at(tokens, profile, imported_at_unix)
}

pub(crate) fn import_tokens_at(
    tokens: ClaudeIssuedTokens,
    profile: ClaudeProfile,
    imported_at_unix: u64,
) -> Result<ClaudeOAuthImport, ClaudeOAuthMaterialError> {
    let ClaudeIssuedTokens {
        access_token,
        refresh_token,
        expires_in,
        refresh_token_expires_in,
        scope,
    } = tokens;
    // A sign-in always issues both tokens and names what it granted.
    let refresh_token = refresh_token.ok_or(ClaudeOAuthMaterialError::Invalid)?;
    let scopes = parse_scopes(scope.as_deref().ok_or(ClaudeOAuthMaterialError::Invalid)?)?;
    let account_hint = profile.email.filter(|email| valid_account_hint(email));
    let rate_limit_tier = profile
        .rate_limit_tier
        .filter(|tier| valid_rate_limit_tier(tier));
    let credential = ClaudeOAuthCredential {
        version: BUNDLE_VERSION,
        access_token,
        refresh_token,
        expires_at_unix: access_token_expiry(imported_at_unix, expires_in)?,
        refresh_expires_at_unix: refresh_token_expiry(imported_at_unix, refresh_token_expires_in)?,
        scopes,
        subscription_type: profile.subscription_type,
        rate_limit_tier,
        refreshed_at_unix: imported_at_unix,
    };
    credential.validate()?;
    Ok(ClaudeOAuthImport {
        bundle: credential.to_bundle()?,
        account_hint,
    })
}

fn access_token_expiry(now: u64, expires_in: u64) -> Result<u64, ClaudeOAuthMaterialError> {
    if now == 0
        || !(MIN_ACCESS_TOKEN_LIFETIME_SECONDS..=MAX_ACCESS_TOKEN_LIFETIME_SECONDS)
            .contains(&expires_in)
    {
        return Err(ClaudeOAuthMaterialError::Invalid);
    }
    now.checked_add(expires_in)
        .ok_or(ClaudeOAuthMaterialError::Invalid)
}

fn refresh_token_expiry(
    now: u64,
    expires_in: Option<u64>,
) -> Result<Option<u64>, ClaudeOAuthMaterialError> {
    expires_in
        .map(|seconds| {
            if !(1..=MAX_REFRESH_TOKEN_LIFETIME_SECONDS).contains(&seconds) {
                return Err(ClaudeOAuthMaterialError::Invalid);
            }
            now.checked_add(seconds)
                .ok_or(ClaudeOAuthMaterialError::Invalid)
        })
        .transpose()
}

/// Whether every granted scope is one Codewire's sign-in asks for (the six
/// the owner accepted for delivery on 2026-10-14). A refresh may replace the
/// stored set, so a scope Claude adds later is never delivered silently.
pub(crate) fn within_sign_in_scopes(scopes: &[String]) -> bool {
    scopes
        .iter()
        .all(|scope| crate::provider_oauth::claude::CLAUDE_SIGN_IN_SCOPES.contains(&scope.as_str()))
}

/// The granted scopes, in the provider's order, without duplicates. Every
/// required scope must be present and no forbidden one.
pub(crate) fn parse_scopes(value: &str) -> Result<Vec<String>, ClaudeOAuthMaterialError> {
    let mut scopes = Vec::new();
    for scope in value.split(' ').filter(|scope| !scope.is_empty()) {
        if scopes.len() >= MAX_SCOPES {
            return Err(ClaudeOAuthMaterialError::Invalid);
        }
        if !scopes.iter().any(|existing: &String| existing == scope) {
            scopes.push(scope.to_owned());
        }
    }
    if !valid_scopes(&scopes) {
        return Err(ClaudeOAuthMaterialError::Invalid);
    }
    Ok(scopes)
}

fn valid_scopes(scopes: &[String]) -> bool {
    !scopes.is_empty()
        && scopes.len() <= MAX_SCOPES
        && scopes.iter().all(|scope| {
            !scope.is_empty()
                && scope.len() <= MAX_SCOPE_BYTES
                && scope.bytes().all(|byte| {
                    byte.is_ascii_lowercase()
                        || byte.is_ascii_digit()
                        || matches!(byte, b':' | b'_' | b'-' | b'.')
                })
        })
        && scopes
            .iter()
            .enumerate()
            .all(|(index, scope)| !scopes[..index].contains(scope))
        && REQUIRED_SCOPES
            .iter()
            .all(|required| scopes.iter().any(|scope| scope == required))
        && !scopes
            .iter()
            .any(|scope| FORBIDDEN_SCOPES.contains(&scope.as_str()))
}

fn valid_token(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_TOKEN_BYTES
        && value
            .bytes()
            .all(|byte| byte.is_ascii_graphic() && byte != b'"' && byte != b'\\')
}

fn valid_rate_limit_tier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_RATE_LIMIT_TIER_BYTES
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
}

fn valid_account_hint(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_ACCOUNT_HINT_BYTES
        && value.trim() == value
        && value.chars().all(|character| !character.is_control())
}

#[cfg(test)]
mod tests {
    #[test]
    fn only_the_sign_in_scopes_are_deliverable() {
        let scopes = |list: &[&str]| {
            list.iter()
                .map(|scope| (*scope).to_owned())
                .collect::<Vec<_>>()
        };
        assert!(super::within_sign_in_scopes(&scopes(
            &crate::provider_oauth::claude::CLAUDE_SIGN_IN_SCOPES
        )));
        assert!(super::within_sign_in_scopes(&scopes(&[
            "user:inference",
            "user:profile"
        ])));
        for widened in [
            &["user:inference", "user:profile", "user:billing"][..],
            &["user:inference", "user:profile", "org:create_api_key"],
        ] {
            assert!(
                !super::within_sign_in_scopes(&scopes(widened)),
                "{widened:?}"
            );
        }
    }

    use super::*;

    const NOW: u64 = 1_800_000_000;
    const SCOPES: &str =
        "user:profile user:inference user:sessions:claude_code user:mcp_servers user:file_upload";

    fn issued(scope: Option<&str>) -> ClaudeIssuedTokens {
        ClaudeIssuedTokens {
            access_token: Zeroizing::new("synthetic-claude-access".into()),
            refresh_token: Some(Zeroizing::new("synthetic-claude-refresh".into())),
            expires_in: 28_800,
            refresh_token_expires_in: None,
            scope: scope.map(str::to_owned),
        }
    }

    fn profile() -> ClaudeProfile {
        ClaudeProfile {
            email: Some("person@example.test".into()),
            subscription_type: ClaudeSubscriptionType::from_organization_type("claude_max"),
            rate_limit_tier: Some("default_claude_max_20x".into()),
        }
    }

    fn credential() -> ClaudeOAuthCredential {
        let (bundle, _) = import_tokens_at(issued(Some(SCOPES)), profile(), NOW)
            .unwrap()
            .into_parts();
        ClaudeOAuthCredential::parse(bundle.as_bytes()).unwrap()
    }

    #[test]
    fn a_sign_in_normalizes_with_its_plan_scopes_and_expiry() {
        let imported = import_tokens_at(issued(Some(SCOPES)), profile(), NOW).unwrap();
        assert_eq!(imported.account_hint(), Some("person@example.test"));
        let (bundle, _) = imported.into_parts();
        let credential = ClaudeOAuthCredential::parse(bundle.as_bytes()).unwrap();
        assert_eq!(credential.access_token(), "synthetic-claude-access");
        assert_eq!(credential.refresh_token(), "synthetic-claude-refresh");
        assert_eq!(credential.expires_at_unix(), NOW + 28_800);
        assert_eq!(credential.refresh_expires_at_unix(), None);
        assert_eq!(
            credential.scopes(),
            [
                "user:profile",
                "user:inference",
                "user:sessions:claude_code",
                "user:mcp_servers",
                "user:file_upload"
            ]
        );
        assert_eq!(
            credential.subscription_type(),
            Some(ClaudeSubscriptionType::Max)
        );
        assert_eq!(credential.rate_limit_tier(), Some("default_claude_max_20x"));
        assert_eq!(credential.refreshed_at_unix(), NOW);
    }

    #[test]
    fn the_plan_follows_claude_codes_organization_type_mapping() {
        for (organization_type, expected) in [
            ("claude_max", Some("max")),
            ("claude_pro", Some("pro")),
            ("claude_team", Some("team")),
            ("claude_enterprise", Some("enterprise")),
            ("claude_free", None),
            ("", None),
            ("CLAUDE_MAX", None),
        ] {
            assert_eq!(
                ClaudeSubscriptionType::from_organization_type(organization_type)
                    .map(ClaudeSubscriptionType::as_str),
                expected
            );
        }
        // A profile without a plan is still a sign-in, with no plan label.
        let (bundle, hint) = import_tokens_at(issued(Some(SCOPES)), ClaudeProfile::default(), NOW)
            .unwrap()
            .into_parts();
        assert_eq!(hint, None);
        let credential = ClaudeOAuthCredential::parse(bundle.as_bytes()).unwrap();
        assert_eq!(credential.subscription_type(), None);
        assert_eq!(credential.rate_limit_tier(), None);
    }

    #[test]
    fn a_sign_in_without_both_tokens_or_required_scopes_is_refused() {
        let mut missing_refresh = issued(Some(SCOPES));
        missing_refresh.refresh_token = None;
        assert!(import_tokens_at(missing_refresh, profile(), NOW).is_err());
        assert!(import_tokens_at(issued(None), profile(), NOW).is_err());
        for scope in [
            "user:inference",
            "user:profile",
            "user:profile user:inference Bad",
            "",
        ] {
            assert!(
                import_tokens_at(issued(Some(scope)), profile(), NOW).is_err(),
                "{scope}"
            );
        }
        for expires_in in [0, 59, MAX_ACCESS_TOKEN_LIFETIME_SECONDS + 1] {
            let mut tokens = issued(Some(SCOPES));
            tokens.expires_in = expires_in;
            assert!(import_tokens_at(tokens, profile(), NOW).is_err());
        }
        let mut tokens = issued(Some(SCOPES));
        tokens.access_token = Zeroizing::new("has space".into());
        assert!(import_tokens_at(tokens, profile(), NOW).is_err());
        // A malformed tier is dropped, not stored.
        let mut odd = profile();
        odd.rate_limit_tier = Some("tier with spaces".into());
        let (bundle, _) = import_tokens_at(issued(Some(SCOPES)), odd, NOW)
            .unwrap()
            .into_parts();
        assert_eq!(
            ClaudeOAuthCredential::parse(bundle.as_bytes())
                .unwrap()
                .rate_limit_tier(),
            None
        );
    }

    #[test]
    fn a_login_that_can_create_api_keys_is_refused_when_stored() {
        for scope in [
            "user:inference user:profile",
            "user:profile user:inference user:plugins",
            SCOPES,
        ] {
            assert!(
                import_tokens_at(issued(Some(scope)), profile(), NOW).is_ok(),
                "{scope}"
            );
        }
        let widened = format!("{SCOPES} org:create_api_key");
        for scope in [
            "user:inference user:profile org:create_api_key",
            "org:create_api_key user:profile",
            "org:create_api_key",
            widened.as_str(),
        ] {
            assert_eq!(
                import_tokens_at(issued(Some(scope)), profile(), NOW).err(),
                Some(ClaudeOAuthMaterialError::Invalid),
                "{scope}"
            );
        }
        // A refresh that adds it is refused rather than stored.
        assert_eq!(
            credential()
                .refreshed(
                    ClaudeIssuedTokens {
                        access_token: Zeroizing::new("widened".into()),
                        refresh_token: None,
                        expires_in: 3_600,
                        refresh_token_expires_in: None,
                        scope: Some("user:inference user:profile org:create_api_key".into()),
                    },
                    NOW + 100,
                )
                .err(),
            Some(ClaudeOAuthMaterialError::Invalid)
        );
        // Stored material that carries it does not parse.
        let (bundle, _) = import_tokens_at(issued(Some(SCOPES)), profile(), NOW)
            .unwrap()
            .into_parts();
        let mut value = serde_json::from_slice::<serde_json::Value>(bundle.as_bytes()).unwrap();
        value["scopes"]
            .as_array_mut()
            .unwrap()
            .push(serde_json::json!("org:create_api_key"));
        assert_eq!(
            ClaudeOAuthCredential::parse(&serde_json::to_vec(&value).unwrap()).err(),
            Some(ClaudeOAuthMaterialError::Invalid)
        );
    }

    #[test]
    fn refresh_rotates_or_keeps_the_refresh_token_and_refuses_a_scope_shrink() {
        let rotated = credential()
            .refreshed(
                ClaudeIssuedTokens {
                    access_token: Zeroizing::new("rotated-access".into()),
                    refresh_token: Some(Zeroizing::new("rotated-refresh".into())),
                    expires_in: 3_600,
                    refresh_token_expires_in: Some(86_400),
                    scope: None,
                },
                NOW + 100,
            )
            .unwrap();
        assert_eq!(rotated.access_token(), "rotated-access");
        assert_eq!(rotated.refresh_token(), "rotated-refresh");
        assert_eq!(rotated.expires_at_unix(), NOW + 3_700);
        assert_eq!(rotated.refresh_expires_at_unix(), Some(NOW + 86_500));
        assert_eq!(rotated.refreshed_at_unix(), NOW + 100);
        // The plan survives a refresh.
        assert_eq!(
            rotated.subscription_type(),
            Some(ClaudeSubscriptionType::Max)
        );

        // Without a returned refresh token the previous one stays, with its
        // known expiry.
        let kept = rotated
            .refreshed(
                ClaudeIssuedTokens {
                    access_token: Zeroizing::new("second-access".into()),
                    refresh_token: None,
                    expires_in: 3_600,
                    refresh_token_expires_in: None,
                    scope: Some("user:inference user:profile".into()),
                },
                NOW + 200,
            )
            .unwrap();
        assert_eq!(kept.refresh_token(), "rotated-refresh");
        assert_eq!(kept.refresh_expires_at_unix(), Some(NOW + 86_500));
        assert_eq!(kept.scopes(), ["user:inference", "user:profile"]);

        // A rotated token without a reported expiry has none.
        let unknown = credential()
            .refreshed(
                ClaudeIssuedTokens {
                    access_token: Zeroizing::new("third-access".into()),
                    refresh_token: Some(Zeroizing::new("third-refresh".into())),
                    expires_in: 3_600,
                    refresh_token_expires_in: None,
                    scope: None,
                },
                NOW + 300,
            )
            .unwrap();
        assert_eq!(unknown.refresh_expires_at_unix(), None);

        // Losing inference or the profile is refused.
        for scope in ["user:inference", "user:profile user:mcp_servers"] {
            assert!(
                credential()
                    .refreshed(
                        ClaudeIssuedTokens {
                            access_token: Zeroizing::new("shrunk".into()),
                            refresh_token: None,
                            expires_in: 3_600,
                            refresh_token_expires_in: None,
                            scope: Some(scope.into()),
                        },
                        NOW + 100,
                    )
                    .is_err(),
                "{scope}"
            );
        }
        for expires_in in [0, MAX_ACCESS_TOKEN_LIFETIME_SECONDS + 1] {
            assert!(
                credential()
                    .refreshed(
                        ClaudeIssuedTokens {
                            access_token: Zeroizing::new("odd".into()),
                            refresh_token: None,
                            expires_in,
                            refresh_token_expires_in: None,
                            scope: None,
                        },
                        NOW + 100,
                    )
                    .is_err()
            );
        }
    }

    #[test]
    fn refresh_window_is_five_minutes_and_a_minimum_is_capped_at_half_the_lifetime() {
        let credential = credential();
        let expiry = NOW + 28_800;
        assert!(!credential.should_refresh(expiry - 301));
        assert!(credential.should_refresh(expiry - 300));
        // Thirty minutes of an eight-hour token.
        let minimum = 30 * 60;
        assert!(!credential.should_refresh_within(expiry - minimum - 1, minimum));
        assert!(credential.should_refresh_within(expiry - minimum, minimum));
        // A forty-minute token needs only twenty: a fresh one never refreshes.
        let short = ClaudeOAuthCredential {
            expires_at_unix: NOW + 2_400,
            ..credential
        };
        assert!(!short.should_refresh_within(NOW, minimum));
        assert!(short.should_refresh_within(NOW + 1_200, minimum));
    }

    #[test]
    fn the_envelope_is_closed_bounded_and_never_formats_material() {
        let (bundle, _) = import_tokens_at(issued(Some(SCOPES)), profile(), NOW)
            .unwrap()
            .into_parts();
        let mut value = serde_json::from_slice::<serde_json::Value>(bundle.as_bytes()).unwrap();
        value["destination"] = serde_json::json!("https://evil.example");
        assert_eq!(
            ClaudeOAuthCredential::parse(&serde_json::to_vec(&value).unwrap()).err(),
            Some(ClaudeOAuthMaterialError::Invalid)
        );
        // A raw setup token is not a sign-in.
        assert_eq!(
            ClaudeOAuthCredential::parse(b"sk-ant-oat01-synthetic").err(),
            Some(ClaudeOAuthMaterialError::Invalid)
        );
        assert_eq!(
            ClaudeOAuthCredential::parse(&vec![b' '; MAX_BUNDLE_BYTES + 1]).err(),
            Some(ClaudeOAuthMaterialError::TooLarge)
        );
        assert_eq!(
            ClaudeOAuthMaterialError::Invalid.to_string(),
            "Claude sign-in material is invalid or unsupported"
        );
    }
}
