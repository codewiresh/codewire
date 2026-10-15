//! One of Codewire's listed direct delivery exceptions: the Sandbox creator's
//! own personal Codex ChatGPT login, sealed to a fresh recipient key held by
//! the workspace daemon, which writes it as Codex's `~/.codex/auth.json`. See
//! docs/dev/SECRETS-AND-CREDENTIALS.md, "Direct delivery exceptions".
//!
//! This is a transport codec, not authority. The broker decides delivery and
//! the authenticated runtime channel authenticates the sender; a sealed box
//! hides the login from relays but proves nothing about who sealed it.
//!
//! The plaintext carries the access token, ID token, account ID and refresh
//! time only. It has no refresh-token field: the refresh token never leaves
//! Codewire. Its own magic and framing keep it apart from environment
//! projections sealed to the same kind of recipient key.

use std::fmt;

use crypto_box::{PublicKey, SecretKey};
use rand::rngs::OsRng;
use thiserror::Error;
use zeroize::Zeroizing;

use crate::validate_projection_recipient;

/// A delivery cannot outlive the request that asked for it by more than this.
pub const MAX_CODEX_LOGIN_LIFETIME_MS: u64 = 30_000;
/// Each of the access token and the ID token.
pub const MAX_CODEX_LOGIN_TOKEN_BYTES: usize = 64 * 1024;
pub const MAX_CODEX_LOGIN_ACCOUNT_ID_BYTES: usize = 1024;
pub const MAX_CODEX_LOGIN_CREDENTIAL_ID_BYTES: usize = 128;

/// Outer framing, outside the sealed box.
const SEALED_MAGIC: &[u8; 8] = b"CWCDXS01";
/// Inner domain, inside the sealed box, before every bound field.
const MAGIC: &[u8; 8] = b"CWCDXL01";
const SEAL_OVERHEAD: usize = 48;
const CONTEXT_BYTES: usize = 16 + 8 + 16 + 8;
const BINDING_BYTES: usize = MAGIC.len() + CONTEXT_BYTES + 32;
const FIXED_BYTES: usize = BINDING_BYTES + 8 + 8 + 8;
const MAX_PLAINTEXT_BYTES: usize = FIXED_BYTES
    + 2
    + MAX_CODEX_LOGIN_CREDENTIAL_ID_BYTES
    + 2 * (4 + MAX_CODEX_LOGIN_TOKEN_BYTES)
    + 2
    + MAX_CODEX_LOGIN_ACCOUNT_ID_BYTES;
const MIN_PLAINTEXT_BYTES: usize = FIXED_BYTES + 2 + 1 + 2 * (4 + 1) + 2 + 1;

/// The largest sealed login any consumer accepts. Checked before allocation
/// or decryption.
pub const MAX_SEALED_CODEX_LOGIN_BYTES: usize =
    SEALED_MAGIC.len() + SEAL_OVERHEAD + MAX_PLAINTEXT_BYTES;
const MIN_SEALED_CODEX_LOGIN_BYTES: usize =
    SEALED_MAGIC.len() + SEAL_OVERHEAD + MIN_PLAINTEXT_BYTES;

/// The one request a sealed login answers. The workspace daemon knows every
/// field before it asks; the broker seals all of them, so a login cannot be
/// replayed into another environment, generation, request or recipient, or
/// opened after its deadline.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CodexLoginContext {
    pub environment_id: [u8; 16],
    pub environment_generation: u64,
    pub request_id: [u8; 16],
    pub deadline_unix_ms: u64,
}

impl CodexLoginContext {
    /// Valid only with nonzero coordinates and a deadline at most
    /// [`MAX_CODEX_LOGIN_LIFETIME_MS`] away and not yet passed.
    pub fn validate_at(&self, now_unix_ms: u64) -> Result<(), CodexLoginError> {
        let remaining = self.deadline_unix_ms.checked_sub(now_unix_ms);
        if self.environment_id == [0; 16]
            || self.environment_generation == 0
            || self.request_id == [0; 16]
            || !remaining
                .is_some_and(|remaining| (1..=MAX_CODEX_LOGIN_LIFETIME_MS).contains(&remaining))
        {
            return Err(CodexLoginError::InvalidContext);
        }
        Ok(())
    }

    fn encode(&self, bytes: &mut Vec<u8>) {
        bytes.extend_from_slice(&self.environment_id);
        bytes.extend_from_slice(&self.environment_generation.to_be_bytes());
        bytes.extend_from_slice(&self.request_id);
        bytes.extend_from_slice(&self.deadline_unix_ms.to_be_bytes());
    }
}

/// Which stored credential version a login came from, sealed with it. The
/// daemon cannot know it in advance; it compares it with what it last wrote so
/// that it never replaces a login with an older generation of the same
/// credential.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CodexLoginBinding {
    pub credential_id: String,
    pub revocation_generation: u64,
    pub material_generation: u64,
}

impl CodexLoginBinding {
    /// Also the Claude login's binding (`claude_login.rs`).
    pub(crate) fn validate(&self) -> Result<(), CodexLoginError> {
        if self.credential_id.is_empty()
            || self.credential_id.len() > MAX_CODEX_LOGIN_CREDENTIAL_ID_BYTES
            || !self.credential_id.bytes().all(|byte| {
                byte.is_ascii_lowercase() || byte.is_ascii_digit() || b"-_.".contains(&byte)
            })
            || self.revocation_generation == 0
            || self.material_generation == 0
        {
            return Err(CodexLoginError::InvalidLogin);
        }
        Ok(())
    }

    /// Whether a login bound to `self` may replace one already written from
    /// `previous`: any other credential, or the same credential at the same
    /// or a later material generation.
    pub fn may_replace(&self, previous: &Self) -> bool {
        self.credential_id != previous.credential_id
            || self.material_generation >= previous.material_generation
    }
}

/// The plaintext Codex needs for its own ChatGPT login. Deliberately not
/// `Clone`, not serializable, redacted in `Debug`, and without any field for a
/// refresh token. Token buffers are zeroized on drop.
pub struct CodexLogin {
    access_token: Zeroizing<String>,
    id_token: Zeroizing<String>,
    account_id: String,
    refreshed_at_unix: u64,
}

impl CodexLogin {
    /// Bounded tokens and account ID of printable ASCII without `"` or `\`,
    /// so each can be written into JSON verbatim, and a nonzero refresh time.
    pub fn new(
        access_token: Zeroizing<String>,
        id_token: Zeroizing<String>,
        account_id: String,
        refreshed_at_unix: u64,
    ) -> Result<Self, CodexLoginError> {
        let login = Self {
            access_token,
            id_token,
            account_id,
            refreshed_at_unix,
        };
        login.validate()?;
        Ok(login)
    }

    fn validate(&self) -> Result<(), CodexLoginError> {
        if !valid_text(&self.access_token, MAX_CODEX_LOGIN_TOKEN_BYTES)
            || !valid_text(&self.id_token, MAX_CODEX_LOGIN_TOKEN_BYTES)
            || !valid_text(&self.account_id, MAX_CODEX_LOGIN_ACCOUNT_ID_BYTES)
            || self.refreshed_at_unix == 0
        {
            return Err(CodexLoginError::InvalidLogin);
        }
        Ok(())
    }

    pub fn access_token(&self) -> &str {
        &self.access_token
    }

    pub fn id_token(&self) -> &str {
        &self.id_token
    }

    pub fn account_id(&self) -> &str {
        &self.account_id
    }

    /// When the broker last obtained these tokens, as Codex's `last_refresh`.
    pub fn refreshed_at_unix(&self) -> u64 {
        self.refreshed_at_unix
    }
}

impl fmt::Debug for CodexLogin {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CodexLogin")
            .field("tokens", &"[REDACTED]")
            .field("refreshed_at_unix", &self.refreshed_at_unix)
            .finish_non_exhaustive()
    }
}

/// One opened delivery: the login and the credential version it came from.
#[derive(Debug)]
pub struct OpenedCodexLogin {
    pub binding: CodexLoginBinding,
    pub login: CodexLogin,
}

/// Seal one already-authorized login for the recipient named by `context`'s
/// request. Encryption grants nothing and does not identify the sender.
pub fn seal_codex_login(
    login: &CodexLogin,
    binding: &CodexLoginBinding,
    context: &CodexLoginContext,
    recipient: [u8; 32],
    now_unix_ms: u64,
) -> Result<Vec<u8>, CodexLoginError> {
    context.validate_at(now_unix_ms)?;
    validate_projection_recipient(recipient).map_err(|_| CodexLoginError::InvalidEnvelope)?;
    binding.validate()?;
    login.validate()?;
    let mut plaintext = Zeroizing::new(Vec::with_capacity(
        FIXED_BYTES
            + 2
            + binding.credential_id.len()
            + 8
            + login.access_token.len()
            + login.id_token.len()
            + 2
            + login.account_id.len(),
    ));
    plaintext.extend_from_slice(MAGIC);
    context.encode(&mut plaintext);
    plaintext.extend_from_slice(&recipient);
    plaintext.extend_from_slice(&binding.revocation_generation.to_be_bytes());
    plaintext.extend_from_slice(&binding.material_generation.to_be_bytes());
    plaintext.extend_from_slice(&login.refreshed_at_unix.to_be_bytes());
    put_u16(&mut plaintext, binding.credential_id.as_bytes());
    put_u32(&mut plaintext, login.access_token.as_bytes());
    put_u32(&mut plaintext, login.id_token.as_bytes());
    put_u16(&mut plaintext, login.account_id.as_bytes());
    let sealed = PublicKey::from(recipient)
        .seal(&mut OsRng, &plaintext)
        .map_err(|_| CodexLoginError::InvalidEnvelope)?;
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
    expected: &CodexLoginContext,
    now_unix_ms: u64,
) -> Result<OpenedCodexLogin, CodexLoginError> {
    expected.validate_at(now_unix_ms)?;
    if !(MIN_SEALED_CODEX_LOGIN_BYTES..=MAX_SEALED_CODEX_LOGIN_BYTES).contains(&ciphertext.len()) {
        return Err(CodexLoginError::InvalidEnvelope);
    }
    let sealed = ciphertext
        .strip_prefix(SEALED_MAGIC.as_slice())
        .ok_or(CodexLoginError::InvalidEnvelope)?;
    let plaintext = Zeroizing::new(
        recipient
            .unseal(sealed)
            .map_err(|_| CodexLoginError::InvalidEnvelope)?,
    );
    let mut binding = Vec::with_capacity(BINDING_BYTES);
    binding.extend_from_slice(MAGIC);
    expected.encode(&mut binding);
    binding.extend_from_slice(&recipient.public_key().to_bytes());
    let mut rest = plaintext
        .strip_prefix(binding.as_slice())
        .ok_or(CodexLoginError::InvalidEnvelope)?;
    let revocation_generation = read_u64(&mut rest)?;
    let material_generation = read_u64(&mut rest)?;
    let refreshed_at_unix = read_u64(&mut rest)?;
    let mut credential_id = read_string(&mut rest, 2)?;
    let access_token = read_string(&mut rest, 4)?;
    let id_token = read_string(&mut rest, 4)?;
    let mut account_id = read_string(&mut rest, 2)?;
    if !rest.is_empty() {
        return Err(CodexLoginError::InvalidEnvelope);
    }
    let binding = CodexLoginBinding {
        credential_id: std::mem::take(&mut *credential_id),
        revocation_generation,
        material_generation,
    };
    binding.validate()?;
    let login = CodexLogin::new(
        access_token,
        id_token,
        std::mem::take(&mut *account_id),
        refreshed_at_unix,
    )?;
    Ok(OpenedCodexLogin { binding, login })
}

fn valid_text(value: &str, maximum: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum
        && value
            .bytes()
            .all(|byte| byte.is_ascii_graphic() && byte != b'"' && byte != b'\\')
}

fn put_u16(bytes: &mut Vec<u8>, value: &[u8]) {
    // Callers validated every u16-framed field to at most 1 KiB.
    bytes.extend_from_slice(&(value.len() as u16).to_be_bytes());
    bytes.extend_from_slice(value);
}

fn put_u32(bytes: &mut Vec<u8>, value: &[u8]) {
    bytes.extend_from_slice(&(value.len() as u32).to_be_bytes());
    bytes.extend_from_slice(value);
}

fn take<'a>(bytes: &mut &'a [u8], count: usize) -> Result<&'a [u8], CodexLoginError> {
    let (value, remaining) = bytes
        .split_at_checked(count)
        .ok_or(CodexLoginError::InvalidEnvelope)?;
    *bytes = remaining;
    Ok(value)
}

fn read_u64(bytes: &mut &[u8]) -> Result<u64, CodexLoginError> {
    Ok(u64::from_be_bytes(
        take(bytes, 8)?
            .try_into()
            .map_err(|_| CodexLoginError::InvalidEnvelope)?,
    ))
}

/// Every decoded field is copied into a zeroizing owner, including when it
/// is not UTF-8.
fn read_string(bytes: &mut &[u8], width: usize) -> Result<Zeroizing<String>, CodexLoginError> {
    let length = take(bytes, width)?
        .iter()
        .fold(0_usize, |length, byte| (length << 8) | usize::from(*byte));
    let value = Zeroizing::new(take(bytes, length)?.to_vec());
    let text = std::str::from_utf8(&value).map_err(|_| CodexLoginError::InvalidEnvelope)?;
    Ok(Zeroizing::new(text.to_owned()))
}

/// Errors never include tokens, account IDs, plaintext or ciphertext.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum CodexLoginError {
    #[error("Codex login context is invalid or expired")]
    InvalidContext,
    #[error("Codex login values are invalid or exceed limits")]
    InvalidLogin,
    #[error("Codex login envelope is invalid")]
    InvalidEnvelope,
}

#[cfg(test)]
mod tests;
