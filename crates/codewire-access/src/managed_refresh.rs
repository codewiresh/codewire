//! The refresh tokens Codewire writes into an agent's own login file in place
//! of the real one, which never leaves Codewire (docs/dev/SECRETS-AND-CREDENTIALS.md,
//! "Direct delivery exceptions"). Each is a public marker, never a credential:
//! the daemon writes it, and the credential broker recognises it when the
//! agent sends it back to refresh.

/// The refresh token Codewire writes into Codex's `auth.json`. It must not be
/// empty: `codex logout` revokes the refresh token, or the access token when
/// the refresh token is empty, and Codewire's access token must stay usable
/// by the creator's other Sandboxes.
pub const CODEX_MANAGED_REFRESH_TOKEN: &str = "codewire-managed-no-refresh-token";
const _: () = assert!(!CODEX_MANAGED_REFRESH_TOKEN.is_empty());

/// The public managed refresh marker Codewire writes into Antigravity's
/// `~/.gemini/antigravity-cli/antigravity-oauth-token` file when interception
/// is active (#6555). Never a real Google refresh token; the broker recognises
/// it on `POST https://oauth2.googleapis.com/token` and returns the
/// environment's placeholder.
pub const ANTIGRAVITY_MANAGED_REFRESH_TOKEN: &str = CODEX_MANAGED_REFRESH_TOKEN;
const _: () = assert!(!ANTIGRAVITY_MANAGED_REFRESH_TOKEN.is_empty());

/// The start of the refresh token Codewire writes into Claude Code's
/// `claudeAiOauth`, which a fresh nonce of [`CLAUDE_MANAGED_REFRESH_NONCE_LENGTH`]
/// lowercase hexadecimal characters follows. It is never empty: Claude Code
/// reads an empty refresh token as a dead login. The nonce changes with every
/// token written, because Claude Code remembers a refused refresh token as
/// dead for the life of its process.
pub const CLAUDE_MANAGED_REFRESH_TOKEN_PREFIX: &str = "codewire-managed-no-refresh-token-";
const _: () = assert!(!CLAUDE_MANAGED_REFRESH_TOKEN_PREFIX.is_empty());

/// The random bytes a Claude marker's nonce encodes.
pub const CLAUDE_MANAGED_REFRESH_NONCE_BYTES: usize = 16;
/// The nonce's length after [`CLAUDE_MANAGED_REFRESH_TOKEN_PREFIX`].
pub const CLAUDE_MANAGED_REFRESH_NONCE_LENGTH: usize = 2 * CLAUDE_MANAGED_REFRESH_NONCE_BYTES;

/// Whether `token` has the form of a Claude refresh token Codewire wrote: the
/// prefix, then exactly [`CLAUDE_MANAGED_REFRESH_NONCE_LENGTH`] lowercase
/// hexadecimal characters. Only the form is checked; no issued nonce is
/// remembered, so every marker of this form is Codewire's.
pub fn is_managed_claude_refresh_token(token: &str) -> bool {
    token
        .strip_prefix(CLAUDE_MANAGED_REFRESH_TOKEN_PREFIX)
        .is_some_and(|nonce| {
            nonce.len() == CLAUDE_MANAGED_REFRESH_NONCE_LENGTH
                && nonce
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        })
}

/// The Claude marker for `nonce`, which the caller draws fresh from a
/// cryptographic random source for every token it writes.
pub fn managed_claude_refresh_token(nonce: [u8; CLAUDE_MANAGED_REFRESH_NONCE_BYTES]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut token = String::with_capacity(
        CLAUDE_MANAGED_REFRESH_TOKEN_PREFIX.len() + CLAUDE_MANAGED_REFRESH_NONCE_LENGTH,
    );
    token.push_str(CLAUDE_MANAGED_REFRESH_TOKEN_PREFIX);
    for byte in nonce {
        token.push(char::from(HEX[usize::from(byte >> 4)]));
        token.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    token
}

#[cfg(test)]
mod tests;
