//! The placeholder-only sealed Antigravity login delivered to the workspace
//! daemon so it can write `~/.gemini/antigravity-cli/antigravity-oauth-token`.
//!
//! Unlike Codex and Claude direct-delivery exceptions, real Google OAuth tokens
//! NEVER leave the broker (#6555): the sealed plaintext carries ONLY the
//! environment's `cwp1_` placeholder, an optional account email hint, and the
//! broker's refresh timestamp. Its own outer and inner magic keep it apart
//! from Codex logins, Claude logins, and environment projections sealed to the
//! same kind of recipient key.

use std::fmt;

use crypto_box::{PublicKey, SecretKey};
use rand::rngs::OsRng;
use thiserror::Error;
use zeroize::Zeroizing;

use crate::validate_projection_recipient;
use crate::{
    CodexLoginBinding as AntigravityLoginBinding, CodexLoginContext as AntigravityLoginContext,
};

const PLACEHOLDER_PREFIX: &str = "cwp1_";
const PLACEHOLDER_LENGTH: usize = PLACEHOLDER_PREFIX.len() + 43;
pub const MAX_ANTIGRAVITY_ACCOUNT_HINT_BYTES: usize = 256;

/// Outer framing, outside the sealed box.
const SEALED_MAGIC: &[u8; 8] = b"CWAGYS01";
/// Inner domain, inside the sealed box, before every bound field.
const MAGIC: &[u8; 8] = b"CWAGYL01";
const SEAL_OVERHEAD: usize = 48;
const CONTEXT_BYTES: usize = 16 + 8 + 16 + 8;
const BINDING_BYTES: usize = MAGIC.len() + CONTEXT_BYTES + 32;
/// Revocation and material generations and refresh time.
const FIXED_BYTES: usize = BINDING_BYTES + 8 + 8 + 8;
const MAX_PLAINTEXT_BYTES: usize = FIXED_BYTES
    + 2
    + crate::MAX_CODEX_LOGIN_CREDENTIAL_ID_BYTES
    + 2
    + PLACEHOLDER_LENGTH
    + 2
    + MAX_ANTIGRAVITY_ACCOUNT_HINT_BYTES;
const MIN_PLAINTEXT_BYTES: usize = FIXED_BYTES + 2 + 1 + 2 + PLACEHOLDER_LENGTH + 2;

/// The largest sealed Antigravity login any consumer accepts. Checked before
/// allocation or decryption.
pub const MAX_SEALED_ANTIGRAVITY_LOGIN_BYTES: usize =
    SEALED_MAGIC.len() + SEAL_OVERHEAD + MAX_PLAINTEXT_BYTES;
const MIN_SEALED_ANTIGRAVITY_LOGIN_BYTES: usize =
    SEALED_MAGIC.len() + SEAL_OVERHEAD + MIN_PLAINTEXT_BYTES;

/// What `agy` needs for its Codewire-managed token file: only the environment's
/// `cwp1_` placeholder, an optional account email hint, and the broker's
/// refresh timestamp. Real Google access or refresh tokens have no field here
/// and fail placeholder validation if passed.
pub struct AntigravityLogin {
    placeholder: Zeroizing<String>,
    account_hint: Option<String>,
    refreshed_at_unix: u64,
}

impl AntigravityLogin {
    /// Construct a placeholder-only Antigravity login. Refuses anything that
    /// is not a canonical `cwp1_` placeholder (48 bytes: `cwp1_` followed by
    /// 43 base64url no-pad characters), any malformed account hint, or a zero
    /// refresh timestamp.
    pub fn new(
        placeholder: Zeroizing<String>,
        account_hint: Option<String>,
        refreshed_at_unix: u64,
    ) -> Result<Self, AntigravityLoginError> {
        let login = Self {
            placeholder,
            account_hint,
            refreshed_at_unix,
        };
        login.validate()?;
        Ok(login)
    }

    fn validate(&self) -> Result<(), AntigravityLoginError> {
        if !is_canonical_placeholder(&self.placeholder) {
            return Err(AntigravityLoginError::InvalidLogin);
        }
        let valid_hint = self.account_hint.as_deref().is_none_or(|hint| {
            !hint.is_empty()
                && hint.len() <= MAX_ANTIGRAVITY_ACCOUNT_HINT_BYTES
                && hint
                    .bytes()
                    .all(|byte| byte.is_ascii_graphic() && byte != b'"' && byte != b'\\')
        });
        if !valid_hint || self.refreshed_at_unix == 0 {
            return Err(AntigravityLoginError::InvalidLogin);
        }
        Ok(())
    }

    pub fn placeholder(&self) -> &str {
        &self.placeholder
    }

    pub fn account_hint(&self) -> Option<&str> {
        self.account_hint.as_deref()
    }

    pub fn refreshed_at_unix(&self) -> u64 {
        self.refreshed_at_unix
    }
}

impl fmt::Debug for AntigravityLogin {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AntigravityLogin")
            .field("placeholder", &"[REDACTED]")
            .field("refreshed_at_unix", &self.refreshed_at_unix)
            .finish_non_exhaustive()
    }
}

/// One opened delivery: the placeholder login and the credential version it
/// came from.
#[derive(Debug)]
pub struct OpenedAntigravityLogin {
    pub binding: AntigravityLoginBinding,
    pub login: AntigravityLogin,
}

/// Seal one already-authorized placeholder-only Antigravity login for the
/// recipient named by `context`'s request.
pub fn seal_antigravity_login(
    login: &AntigravityLogin,
    binding: &AntigravityLoginBinding,
    context: &AntigravityLoginContext,
    recipient: [u8; 32],
    now_unix_ms: u64,
) -> Result<Vec<u8>, AntigravityLoginError> {
    context
        .validate_at(now_unix_ms)
        .map_err(|_| AntigravityLoginError::InvalidContext)?;
    validate_projection_recipient(recipient).map_err(|_| AntigravityLoginError::InvalidEnvelope)?;
    binding
        .validate()
        .map_err(|_| AntigravityLoginError::InvalidLogin)?;
    login.validate()?;
    let hint = login.account_hint.as_deref().unwrap_or("");
    let mut plaintext = Zeroizing::new(Vec::with_capacity(
        FIXED_BYTES
            + 2
            + binding.credential_id.len()
            + 2
            + login.placeholder.len()
            + 2
            + hint.len(),
    ));
    plaintext.extend_from_slice(MAGIC);
    encode_context(context, &mut plaintext);
    plaintext.extend_from_slice(&recipient);
    plaintext.extend_from_slice(&binding.revocation_generation.to_be_bytes());
    plaintext.extend_from_slice(&binding.material_generation.to_be_bytes());
    plaintext.extend_from_slice(&login.refreshed_at_unix.to_be_bytes());
    put_u16(&mut plaintext, binding.credential_id.as_bytes());
    put_u16(&mut plaintext, login.placeholder.as_bytes());
    put_u16(&mut plaintext, hint.as_bytes());
    let sealed = PublicKey::from(recipient)
        .seal(&mut OsRng, &plaintext)
        .map_err(|_| AntigravityLoginError::InvalidEnvelope)?;
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
    expected: &AntigravityLoginContext,
    now_unix_ms: u64,
) -> Result<OpenedAntigravityLogin, AntigravityLoginError> {
    expected
        .validate_at(now_unix_ms)
        .map_err(|_| AntigravityLoginError::InvalidContext)?;
    if !(MIN_SEALED_ANTIGRAVITY_LOGIN_BYTES..=MAX_SEALED_ANTIGRAVITY_LOGIN_BYTES)
        .contains(&ciphertext.len())
    {
        return Err(AntigravityLoginError::InvalidEnvelope);
    }
    let sealed = ciphertext
        .strip_prefix(SEALED_MAGIC.as_slice())
        .ok_or(AntigravityLoginError::InvalidEnvelope)?;
    let plaintext = Zeroizing::new(
        recipient
            .unseal(sealed)
            .map_err(|_| AntigravityLoginError::InvalidEnvelope)?,
    );
    let mut binding = Vec::with_capacity(BINDING_BYTES);
    binding.extend_from_slice(MAGIC);
    encode_context(expected, &mut binding);
    binding.extend_from_slice(&recipient.public_key().to_bytes());
    let mut rest = plaintext
        .strip_prefix(binding.as_slice())
        .ok_or(AntigravityLoginError::InvalidEnvelope)?;
    let revocation_generation = read_u64(&mut rest)?;
    let material_generation = read_u64(&mut rest)?;
    let refreshed_at_unix = read_u64(&mut rest)?;
    let mut credential_id = read_string(&mut rest)?;
    let placeholder = read_string(&mut rest)?;
    let mut account_hint = read_string(&mut rest)?;
    if !rest.is_empty() {
        return Err(AntigravityLoginError::InvalidEnvelope);
    }
    let binding = AntigravityLoginBinding {
        credential_id: std::mem::take(&mut *credential_id),
        revocation_generation,
        material_generation,
    };
    binding
        .validate()
        .map_err(|_| AntigravityLoginError::InvalidLogin)?;
    let login = AntigravityLogin::new(
        placeholder,
        (!account_hint.is_empty()).then(|| std::mem::take(&mut *account_hint)),
        refreshed_at_unix,
    )?;
    Ok(OpenedAntigravityLogin { binding, login })
}

fn is_canonical_placeholder(value: &str) -> bool {
    value.len() == PLACEHOLDER_LENGTH
        && value.strip_prefix(PLACEHOLDER_PREFIX).is_some_and(|rest| {
            rest.bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
        })
}

fn encode_context(context: &AntigravityLoginContext, bytes: &mut Vec<u8>) {
    bytes.extend_from_slice(&context.environment_id);
    bytes.extend_from_slice(&context.environment_generation.to_be_bytes());
    bytes.extend_from_slice(&context.request_id);
    bytes.extend_from_slice(&context.deadline_unix_ms.to_be_bytes());
}

fn put_u16(bytes: &mut Vec<u8>, value: &[u8]) {
    bytes.extend_from_slice(&(value.len() as u16).to_be_bytes());
    bytes.extend_from_slice(value);
}

fn take<'a>(bytes: &mut &'a [u8], count: usize) -> Result<&'a [u8], AntigravityLoginError> {
    let (value, remaining) = bytes
        .split_at_checked(count)
        .ok_or(AntigravityLoginError::InvalidEnvelope)?;
    *bytes = remaining;
    Ok(value)
}

fn read_u64(bytes: &mut &[u8]) -> Result<u64, AntigravityLoginError> {
    Ok(u64::from_be_bytes(
        take(bytes, 8)?
            .try_into()
            .map_err(|_| AntigravityLoginError::InvalidEnvelope)?,
    ))
}

fn read_string(bytes: &mut &[u8]) -> Result<Zeroizing<String>, AntigravityLoginError> {
    let length = u16::from_be_bytes(
        take(bytes, 2)?
            .try_into()
            .map_err(|_| AntigravityLoginError::InvalidEnvelope)?,
    ) as usize;
    let value = Zeroizing::new(take(bytes, length)?.to_vec());
    let text = std::str::from_utf8(&value).map_err(|_| AntigravityLoginError::InvalidEnvelope)?;
    Ok(Zeroizing::new(text.to_owned()))
}

/// Errors never include placeholders, hints, plaintext or ciphertext.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum AntigravityLoginError {
    #[error("Antigravity login context is invalid or expired")]
    InvalidContext,
    #[error("Antigravity login values are invalid or exceed limits")]
    InvalidLogin,
    #[error("Antigravity login envelope is invalid")]
    InvalidEnvelope,
}

#[cfg(test)]
#[path = "antigravity_login_tests.rs"]
mod tests;
