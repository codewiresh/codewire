//! The second listed direct delivery exception: the Sandbox creator's own
//! personal Claude sign-in, sealed to a fresh recipient key held by the
//! workspace daemon, which writes it as `claudeAiOauth` in Claude Code's
//! `~/.claude/.credentials.json`. See docs/dev/SECRETS-AND-CREDENTIALS.md,
//! "Direct delivery exceptions".
//!
//! Like the Codex login, this is a transport codec, not authority. It shares
//! the Codex login's request context and credential binding: the same
//! environment, generation, request, recipient and deadline, and the exact
//! credential version.
//!
//! The plaintext carries the access token, its expiry, the granted scopes, the
//! plan and rate-limit tier, and the refresh time only. It has no
//! refresh-token field: the refresh token never leaves Codewire. Its own magic
//! and framing keep it apart from Codex logins and environment projections
//! sealed to the same kind of recipient key.

use std::fmt;

use crypto_box::{PublicKey, SecretKey};
use rand::rngs::OsRng;
use thiserror::Error;
use zeroize::Zeroizing;

use crate::validate_projection_recipient;
use crate::{CodexLoginBinding as ClaudeLoginBinding, CodexLoginContext as ClaudeLoginContext};

pub const MAX_CLAUDE_LOGIN_TOKEN_BYTES: usize = 16 * 1024;
pub const MAX_CLAUDE_LOGIN_SCOPES: usize = 32;
pub const MAX_CLAUDE_LOGIN_SCOPE_BYTES: usize = 128;
pub const MAX_CLAUDE_LOGIN_TIER_BYTES: usize = 128;
const MAX_SCOPES_TEXT_BYTES: usize = MAX_CLAUDE_LOGIN_SCOPES * (MAX_CLAUDE_LOGIN_SCOPE_BYTES + 1);

/// Outer framing, outside the sealed box.
const SEALED_MAGIC: &[u8; 8] = b"CWCLDS01";
/// Inner domain, inside the sealed box, before every bound field.
const MAGIC: &[u8; 8] = b"CWCLDL01";
const SEAL_OVERHEAD: usize = 48;
const CONTEXT_BYTES: usize = 16 + 8 + 16 + 8;
const BINDING_BYTES: usize = MAGIC.len() + CONTEXT_BYTES + 32;
/// Revocation and material generations, refresh time, expiry and the plan.
const FIXED_BYTES: usize = BINDING_BYTES + 8 + 8 + 8 + 8 + 1;
const MAX_PLAINTEXT_BYTES: usize = FIXED_BYTES
    + 2
    + crate::MAX_CODEX_LOGIN_CREDENTIAL_ID_BYTES
    + 4
    + MAX_CLAUDE_LOGIN_TOKEN_BYTES
    + 2
    + MAX_SCOPES_TEXT_BYTES
    + 2
    + MAX_CLAUDE_LOGIN_TIER_BYTES;
const MIN_PLAINTEXT_BYTES: usize = FIXED_BYTES + 2 + 1 + 4 + 1 + 2 + 1 + 2;

/// The largest sealed login any consumer accepts. Checked before allocation
/// or decryption.
pub const MAX_SEALED_CLAUDE_LOGIN_BYTES: usize =
    SEALED_MAGIC.len() + SEAL_OVERHEAD + MAX_PLAINTEXT_BYTES;
const MIN_SEALED_CLAUDE_LOGIN_BYTES: usize =
    SEALED_MAGIC.len() + SEAL_OVERHEAD + MIN_PLAINTEXT_BYTES;

/// Claude Code's plan names, as its own login stores `subscriptionType`.
const PLANS: [&str; 4] = ["max", "pro", "team", "enterprise"];

/// What Claude Code needs for its own claude.ai login. Deliberately not
/// `Clone`, not serializable, redacted in `Debug`, and without any field for
/// a refresh token. The token buffer is zeroized on drop.
pub struct ClaudeLogin {
    access_token: Zeroizing<String>,
    expires_at_unix_ms: u64,
    scopes: Vec<String>,
    subscription_type: Option<String>,
    rate_limit_tier: Option<String>,
    refreshed_at_unix: u64,
}

impl ClaudeLogin {
    /// A bounded access token of printable ASCII without `"` or `\`, a nonzero
    /// expiry, between one and [`MAX_CLAUDE_LOGIN_SCOPES`] distinct scopes of
    /// `[a-z0-9:_.-]`, an optional plan Claude Code names (`max`, `pro`,
    /// `team` or `enterprise`), an optional tier of `[A-Za-z0-9_.-]`, and a
    /// nonzero refresh time.
    pub fn new(
        access_token: Zeroizing<String>,
        expires_at_unix_ms: u64,
        scopes: Vec<String>,
        subscription_type: Option<String>,
        rate_limit_tier: Option<String>,
        refreshed_at_unix: u64,
    ) -> Result<Self, ClaudeLoginError> {
        let login = Self {
            access_token,
            expires_at_unix_ms,
            scopes,
            subscription_type,
            rate_limit_tier,
            refreshed_at_unix,
        };
        login.validate()?;
        Ok(login)
    }

    fn validate(&self) -> Result<(), ClaudeLoginError> {
        let valid_token = !self.access_token.is_empty()
            && self.access_token.len() <= MAX_CLAUDE_LOGIN_TOKEN_BYTES
            && self
                .access_token
                .bytes()
                .all(|byte| byte.is_ascii_graphic() && byte != b'"' && byte != b'\\');
        let valid_scopes = !self.scopes.is_empty()
            && self.scopes.len() <= MAX_CLAUDE_LOGIN_SCOPES
            && self.scopes.iter().enumerate().all(|(index, scope)| {
                !scope.is_empty()
                    && scope.len() <= MAX_CLAUDE_LOGIN_SCOPE_BYTES
                    && scope.bytes().all(|byte| {
                        byte.is_ascii_lowercase()
                            || byte.is_ascii_digit()
                            || matches!(byte, b':' | b'_' | b'-' | b'.')
                    })
                    && !self.scopes[..index].contains(scope)
            });
        let valid_plan = self
            .subscription_type
            .as_deref()
            .is_none_or(|plan| PLANS.contains(&plan));
        let valid_tier = self.rate_limit_tier.as_deref().is_none_or(|tier| {
            !tier.is_empty()
                && tier.len() <= MAX_CLAUDE_LOGIN_TIER_BYTES
                && tier
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
        });
        if !valid_token
            || self.expires_at_unix_ms == 0
            || !valid_scopes
            || !valid_plan
            || !valid_tier
            || self.refreshed_at_unix == 0
        {
            return Err(ClaudeLoginError::InvalidLogin);
        }
        Ok(())
    }

    pub fn access_token(&self) -> &str {
        &self.access_token
    }

    /// When the access token expires, in milliseconds, as Claude Code stores
    /// `expiresAt`.
    pub fn expires_at_unix_ms(&self) -> u64 {
        self.expires_at_unix_ms
    }

    /// The scopes exactly as granted.
    pub fn scopes(&self) -> &[String] {
        &self.scopes
    }

    pub fn subscription_type(&self) -> Option<&str> {
        self.subscription_type.as_deref()
    }

    pub fn rate_limit_tier(&self) -> Option<&str> {
        self.rate_limit_tier.as_deref()
    }

    /// When the broker last obtained this access token.
    pub fn refreshed_at_unix(&self) -> u64 {
        self.refreshed_at_unix
    }
}

impl fmt::Debug for ClaudeLogin {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ClaudeLogin")
            .field("access_token", &"[REDACTED]")
            .field("expires_at_unix_ms", &self.expires_at_unix_ms)
            .field("refreshed_at_unix", &self.refreshed_at_unix)
            .finish_non_exhaustive()
    }
}

/// One opened delivery: the login and the credential version it came from.
#[derive(Debug)]
pub struct OpenedClaudeLogin {
    pub binding: ClaudeLoginBinding,
    pub login: ClaudeLogin,
}

/// Seal one already-authorized login for the recipient named by `context`'s
/// request. Encryption grants nothing and does not identify the sender.
pub fn seal_claude_login(
    login: &ClaudeLogin,
    binding: &ClaudeLoginBinding,
    context: &ClaudeLoginContext,
    recipient: [u8; 32],
    now_unix_ms: u64,
) -> Result<Vec<u8>, ClaudeLoginError> {
    context
        .validate_at(now_unix_ms)
        .map_err(|_| ClaudeLoginError::InvalidContext)?;
    validate_projection_recipient(recipient).map_err(|_| ClaudeLoginError::InvalidEnvelope)?;
    binding
        .validate()
        .map_err(|_| ClaudeLoginError::InvalidLogin)?;
    login.validate()?;
    let scopes = Zeroizing::new(login.scopes.join(" "));
    let tier = login.rate_limit_tier.as_deref().unwrap_or("");
    let mut plaintext = Zeroizing::new(Vec::with_capacity(
        FIXED_BYTES
            + 2
            + binding.credential_id.len()
            + 4
            + login.access_token.len()
            + 2
            + scopes.len()
            + 2
            + tier.len(),
    ));
    plaintext.extend_from_slice(MAGIC);
    encode_context(context, &mut plaintext);
    plaintext.extend_from_slice(&recipient);
    plaintext.extend_from_slice(&binding.revocation_generation.to_be_bytes());
    plaintext.extend_from_slice(&binding.material_generation.to_be_bytes());
    plaintext.extend_from_slice(&login.refreshed_at_unix.to_be_bytes());
    plaintext.extend_from_slice(&login.expires_at_unix_ms.to_be_bytes());
    plaintext.push(plan_code(login.subscription_type.as_deref()));
    put_u16(&mut plaintext, binding.credential_id.as_bytes());
    put_u32(&mut plaintext, login.access_token.as_bytes());
    put_u16(&mut plaintext, scopes.as_bytes());
    put_u16(&mut plaintext, tier.as_bytes());
    let sealed = PublicKey::from(recipient)
        .seal(&mut OsRng, &plaintext)
        .map_err(|_| ClaudeLoginError::InvalidEnvelope)?;
    let mut bytes = Vec::with_capacity(SEALED_MAGIC.len() + sealed.len());
    bytes.extend_from_slice(SEALED_MAGIC);
    bytes.extend_from_slice(&sealed);
    Ok(bytes)
}

/// Open with the recipient's secret key, which the caller consumes. Every
/// bound field must match `expected` exactly, before its deadline.
pub(crate) fn open(
    recipient: &SecretKey,
    ciphertext: &[u8],
    expected: &ClaudeLoginContext,
    now_unix_ms: u64,
) -> Result<OpenedClaudeLogin, ClaudeLoginError> {
    expected
        .validate_at(now_unix_ms)
        .map_err(|_| ClaudeLoginError::InvalidContext)?;
    if !(MIN_SEALED_CLAUDE_LOGIN_BYTES..=MAX_SEALED_CLAUDE_LOGIN_BYTES).contains(&ciphertext.len())
    {
        return Err(ClaudeLoginError::InvalidEnvelope);
    }
    let sealed = ciphertext
        .strip_prefix(SEALED_MAGIC.as_slice())
        .ok_or(ClaudeLoginError::InvalidEnvelope)?;
    let plaintext = Zeroizing::new(
        recipient
            .unseal(sealed)
            .map_err(|_| ClaudeLoginError::InvalidEnvelope)?,
    );
    let mut binding = Vec::with_capacity(BINDING_BYTES);
    binding.extend_from_slice(MAGIC);
    encode_context(expected, &mut binding);
    binding.extend_from_slice(&recipient.public_key().to_bytes());
    let mut rest = plaintext
        .strip_prefix(binding.as_slice())
        .ok_or(ClaudeLoginError::InvalidEnvelope)?;
    let revocation_generation = read_u64(&mut rest)?;
    let material_generation = read_u64(&mut rest)?;
    let refreshed_at_unix = read_u64(&mut rest)?;
    let expires_at_unix_ms = read_u64(&mut rest)?;
    let plan = take(&mut rest, 1)?[0];
    let mut credential_id = read_string(&mut rest, 2)?;
    let access_token = read_string(&mut rest, 4)?;
    let scopes = read_string(&mut rest, 2)?;
    let mut tier = read_string(&mut rest, 2)?;
    if !rest.is_empty() {
        return Err(ClaudeLoginError::InvalidEnvelope);
    }
    let binding = ClaudeLoginBinding {
        credential_id: std::mem::take(&mut *credential_id),
        revocation_generation,
        material_generation,
    };
    binding
        .validate()
        .map_err(|_| ClaudeLoginError::InvalidLogin)?;
    let login = ClaudeLogin::new(
        access_token,
        expires_at_unix_ms,
        scopes.split(' ').map(str::to_owned).collect(),
        plan_name(plan)?.map(str::to_owned),
        (!tier.is_empty()).then(|| std::mem::take(&mut *tier)),
        refreshed_at_unix,
    )?;
    Ok(OpenedClaudeLogin { binding, login })
}

fn plan_code(plan: Option<&str>) -> u8 {
    plan.and_then(|plan| PLANS.iter().position(|known| *known == plan))
        .map_or(0, |index| index as u8 + 1)
}

fn plan_name(code: u8) -> Result<Option<&'static str>, ClaudeLoginError> {
    match code {
        0 => Ok(None),
        code => PLANS
            .get(usize::from(code) - 1)
            .copied()
            .map(Some)
            .ok_or(ClaudeLoginError::InvalidEnvelope),
    }
}

fn encode_context(context: &ClaudeLoginContext, bytes: &mut Vec<u8>) {
    bytes.extend_from_slice(&context.environment_id);
    bytes.extend_from_slice(&context.environment_generation.to_be_bytes());
    bytes.extend_from_slice(&context.request_id);
    bytes.extend_from_slice(&context.deadline_unix_ms.to_be_bytes());
}

fn put_u16(bytes: &mut Vec<u8>, value: &[u8]) {
    // Callers validated every u16-framed field to well under 64 KiB.
    bytes.extend_from_slice(&(value.len() as u16).to_be_bytes());
    bytes.extend_from_slice(value);
}

fn put_u32(bytes: &mut Vec<u8>, value: &[u8]) {
    bytes.extend_from_slice(&(value.len() as u32).to_be_bytes());
    bytes.extend_from_slice(value);
}

fn take<'a>(bytes: &mut &'a [u8], count: usize) -> Result<&'a [u8], ClaudeLoginError> {
    let (value, remaining) = bytes
        .split_at_checked(count)
        .ok_or(ClaudeLoginError::InvalidEnvelope)?;
    *bytes = remaining;
    Ok(value)
}

fn read_u64(bytes: &mut &[u8]) -> Result<u64, ClaudeLoginError> {
    Ok(u64::from_be_bytes(
        take(bytes, 8)?
            .try_into()
            .map_err(|_| ClaudeLoginError::InvalidEnvelope)?,
    ))
}

/// Every decoded field is copied into a zeroizing owner, including when it
/// is not UTF-8.
fn read_string(bytes: &mut &[u8], width: usize) -> Result<Zeroizing<String>, ClaudeLoginError> {
    let length = take(bytes, width)?
        .iter()
        .fold(0_usize, |length, byte| (length << 8) | usize::from(*byte));
    let value = Zeroizing::new(take(bytes, length)?.to_vec());
    let text = std::str::from_utf8(&value).map_err(|_| ClaudeLoginError::InvalidEnvelope)?;
    Ok(Zeroizing::new(text.to_owned()))
}

/// Errors never include tokens, scopes, plaintext or ciphertext.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum ClaudeLoginError {
    #[error("Claude login context is invalid or expired")]
    InvalidContext,
    #[error("Claude login values are invalid or exceed limits")]
    InvalidLogin,
    #[error("Claude login envelope is invalid")]
    InvalidEnvelope,
}

#[cfg(test)]
#[path = "claude_login_tests.rs"]
mod tests;
