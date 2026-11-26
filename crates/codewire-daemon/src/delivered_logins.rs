//! How a Codewire-delivered agent login is recognised on disk: Codex's
//! `auth.json` and Claude Code's credential store, the listed direct delivery
//! exceptions (docs/dev/SECRETS-AND-CREDENTIALS.md, "Direct delivery
//! exceptions"). The daemon's writers on Linux (`codex_home::login`,
//! `claude_home::login`) write and remove a login by these rules, and
//! a reader of a disk image recognises one by them, such as a local VM's disk
//! snapshot capture on a Linux host or a Mac (#4654). Nothing here touches a
//! file, so every host compiles it.

use serde_json::{Map, Value};
use zeroize::Zeroize as _;

/// A parsed login file. Every string in it is zeroized on drop.
pub(crate) struct Document(pub(crate) Value);

impl Drop for Document {
    fn drop(&mut self) {
        scrub(&mut self.0);
    }
}

/// Zeroize every string in `value`.
pub(crate) fn scrub(value: &mut Value) {
    match value {
        Value::String(text) => text.zeroize(),
        Value::Array(values) => values.iter_mut().for_each(scrub),
        Value::Object(object) => object.values_mut().for_each(scrub),
        _ => {}
    }
}

impl Document {
    /// A JSON object, or nothing.
    pub(crate) fn parse(bytes: &[u8]) -> Option<Self> {
        let document = Self(serde_json::from_slice(bytes).ok()?);
        document.object()?;
        Some(document)
    }

    pub(crate) fn object(&self) -> Option<&Map<String, Value>> {
        self.0.as_object()
    }
}

/// Codex's `auth.json`.
pub mod codex {
    use serde_json::{Map, Value};

    use super::Document;

    /// Codex's login file in its home.
    pub const CODEX_AUTH_FILE_NAME: &str = "auth.json";
    /// The refresh token Codewire writes. It must not be empty: `codex logout`
    /// revokes the refresh token, or the access token when the refresh token is
    /// empty, and Codewire's access token must stay usable by the creator's other
    /// Sandboxes.
    /// Defined in codewire-access, beside the credential broker's recogniser
    /// of it (#3999).
    pub use codewire_access::CODEX_MANAGED_REFRESH_TOKEN;
    const _: () = assert!(!CODEX_MANAGED_REFRESH_TOKEN.is_empty());

    /// `contents` parsed, when it is an `auth.json` Codewire wrote.
    pub(crate) fn codewire_document(contents: &[u8]) -> Option<Document> {
        Document::parse(contents).filter(Document::is_codewire)
    }

    /// `auth.json` as Codex writes it.
    impl Document {
        pub(crate) fn tokens(&self) -> Option<&Map<String, Value>> {
            self.object()?.get("tokens")?.as_object()
        }

        /// Codewire's: ChatGPT mode with exactly the placeholder refresh token.
        pub(crate) fn is_codewire(&self) -> bool {
            self.object()
                .and_then(|object| object.get("auth_mode"))
                .and_then(Value::as_str)
                == Some("chatgpt")
                && self
                    .tokens()
                    .and_then(|tokens| tokens.get("refresh_token"))
                    .and_then(Value::as_str)
                    == Some(CODEX_MANAGED_REFRESH_TOKEN)
        }
    }

    /// Whether `contents` is an `auth.json` Codewire wrote: ChatGPT mode with
    /// exactly the placeholder refresh token. The rule the daemon removes by, for a reader
    /// of a disk image that holds such a file, such as a local VM's disk snapshot
    /// capture (docs/dev/SECRETS-AND-CREDENTIALS.md, "Direct delivery
    /// exceptions").
    pub fn is_codewire_auth_file(contents: &[u8]) -> bool {
        codewire_document(contents).is_some()
    }

    /// Whether `name` in Codex's home is one of Codewire's temporaries beside
    /// `auth.json`.
    pub fn is_codewire_temporary(name: &str) -> bool {
        name.starts_with(&format!(".{CODEX_AUTH_FILE_NAME}.codewire."))
    }

    /// Whether the temporary `name` is a write in progress, which is Codewire's
    /// whatever it holds, so it is removed unread.
    pub fn is_codewire_write_in_progress(name: &str) -> bool {
        is_codewire_temporary(name) && name.ends_with(".new")
    }

    /// Whether the temporary `name` holding `contents` is Codewire's: a write in
    /// progress, or Codewire's login. A user's file set aside stays.
    pub fn is_codewire_leftover(name: &str, contents: &[u8]) -> bool {
        is_codewire_write_in_progress(name)
            || (is_codewire_temporary(name) && is_codewire_auth_file(contents))
    }
}

/// Claude Code's credential store.
pub mod claude {
    use serde_json::{Map, Value};

    use super::Document;

    /// Claude Code's plaintext credential store on Linux, in that directory.
    pub const CLAUDE_CREDENTIALS_FILE_NAME: &str = ".credentials.json";
    /// The member Claude Code reads its claude.ai login from.
    pub const CLAUDE_LOGIN_KEY: &str = "claudeAiOauth";
    /// The top-level member that marks the file as one Codewire wrote a login
    /// into. Claude Code's own writes and its `/logout` keep members they do not
    /// name, so it survives both.
    pub const CLAUDE_MANAGED_MARKER: &str = "codewireManaged";
    /// The start of the refresh token Codewire writes. It is never empty: Claude
    /// Code reads an empty refresh token as a dead login. Defined in
    /// codewire-access, beside the credential broker's recogniser of it
    /// (#3999).
    pub use codewire_access::CLAUDE_MANAGED_REFRESH_TOKEN_PREFIX;
    const _: () = assert!(!CLAUDE_MANAGED_REFRESH_TOKEN_PREFIX.is_empty());
    /// The hexadecimal nonce after [`CLAUDE_MANAGED_REFRESH_TOKEN_PREFIX`].
    #[cfg(test)]
    pub(crate) const NONCE_LENGTH: usize = codewire_access::CLAUDE_MANAGED_REFRESH_NONCE_LENGTH;

    /// What `claudeAiOauth` in a file Codewire may write is.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub(crate) enum OwnLogin {
        /// No `claudeAiOauth`.
        Absent,
        /// Codewire's: it carries the placeholder refresh token.
        Codewire,
        /// Codewire's, cleared by Claude Code after its refresh was refused: an
        /// empty refresh token beside the marker.
        Cleared,
    }

    /// What a store's `contents` hold: `None` for the user's own login or a file
    /// that is not a JSON object.
    pub(crate) fn classify_contents(contents: &[u8]) -> Option<(Document, OwnLogin)> {
        let document = Document::parse(contents)?;
        let login = match document.login() {
            None if document.has_login_key() => return None,
            None => OwnLogin::Absent,
            Some(oauth) => match oauth.get("refreshToken").and_then(Value::as_str) {
                Some(token) if is_placeholder(token) => OwnLogin::Codewire,
                Some("") if document.marked() => OwnLogin::Cleared,
                _ => return None,
            },
        };
        Some((document, login))
    }

    /// Claude Code's credential store.
    impl Document {
        /// `claudeAiOauth`, when it is an object.
        pub(crate) fn login(&self) -> Option<&Map<String, Value>> {
            self.object()?.get(CLAUDE_LOGIN_KEY)?.as_object()
        }

        pub(crate) fn has_login_key(&self) -> bool {
            self.object()
                .is_some_and(|object| object.contains_key(CLAUDE_LOGIN_KEY))
        }

        pub(crate) fn marked(&self) -> bool {
            self.object()
                .and_then(|object| object.get(CLAUDE_MANAGED_MARKER))
                .and_then(Value::as_u64)
                == Some(1)
        }
    }

    /// Whether `token` is a refresh token Codewire wrote.
    pub(crate) fn is_placeholder(token: &str) -> bool {
        codewire_access::is_managed_claude_refresh_token(token)
    }

    /// Whether `contents` is a credential store whose `claudeAiOauth` is
    /// Codewire's: its placeholder refresh token, or the empty one Claude Code
    /// leaves beside the marker once Codewire's login was refused. The rule the
    /// daemon removes by, for a reader of a disk image too, such as a local VM's
    /// disk snapshot capture (docs/dev/SECRETS-AND-CREDENTIALS.md, "Direct
    /// delivery exceptions").
    pub fn holds_codewire_login(contents: &[u8]) -> bool {
        matches!(
            classify_contents(contents),
            Some((_, OwnLogin::Codewire | OwnLogin::Cleared))
        )
    }

    /// Whether `name` in `~/.claude` is one of Codewire's temporaries beside the
    /// store.
    pub fn is_codewire_temporary(name: &str) -> bool {
        name.starts_with(&format!("{CLAUDE_CREDENTIALS_FILE_NAME}.codewire."))
    }

    /// Whether the temporary `name` is a write in progress, which is Codewire's
    /// whatever it holds, so it is removed unread.
    pub fn is_codewire_write_in_progress(name: &str) -> bool {
        is_codewire_temporary(name) && name.ends_with(".new")
    }

    /// Whether the temporary `name` holding `contents` is Codewire's: a write in
    /// progress, or a store holding Codewire's login. A user's store set aside
    /// stays.
    pub fn is_codewire_leftover(name: &str, contents: &[u8]) -> bool {
        is_codewire_write_in_progress(name)
            || (is_codewire_temporary(name) && holds_codewire_login(contents))
    }
}

/// Antigravity CLI's placeholder-backed token file (`~/.gemini/antigravity-cli/antigravity-oauth-token`).
pub mod antigravity {
    use serde_json::{Map, Value};

    use super::Document;

    /// Parent directory under the user's home.
    pub const ANTIGRAVITY_CONFIG_PARENT_DIR: &str = ".gemini";
    /// Subdirectory under `~/.gemini` where `agy` reads its token file.
    pub const ANTIGRAVITY_CONFIG_DIR_NAME: &str = "antigravity-cli";
    /// Antigravity CLI's OAuth token file name.
    pub const ANTIGRAVITY_TOKEN_FILE_NAME: &str = "antigravity-oauth-token";
    /// Public non-secret refresh marker written into the token file (#6555).
    pub use codewire_access::ANTIGRAVITY_MANAGED_REFRESH_TOKEN;
    const _: () = assert!(!ANTIGRAVITY_MANAGED_REFRESH_TOKEN.is_empty());

    /// `contents` parsed when it is an Antigravity token file Codewire wrote.
    pub(crate) fn codewire_document(contents: &[u8]) -> Option<Document> {
        Document::parse(contents).filter(Document::is_codewire_antigravity)
    }

    impl Document {
        pub(crate) fn antigravity_token(&self) -> Option<&Map<String, Value>> {
            self.object()?.get("token")?.as_object()
        }

        /// Codewire's: `auth_method` `"consumer"` with exactly the managed
        /// refresh marker in `token.refresh_token`.
        pub(crate) fn is_codewire_antigravity(&self) -> bool {
            self.object()
                .and_then(|object| object.get("auth_method"))
                .and_then(Value::as_str)
                == Some("consumer")
                && self
                    .antigravity_token()
                    .and_then(|token| token.get("refresh_token"))
                    .and_then(Value::as_str)
                    == Some(ANTIGRAVITY_MANAGED_REFRESH_TOKEN)
        }
    }

    /// Whether `contents` is an Antigravity token file Codewire wrote.
    pub fn is_codewire_token_file(contents: &[u8]) -> bool {
        codewire_document(contents).is_some()
    }

    /// Whether `name` in `~/.gemini/antigravity-cli` is one of Codewire's
    /// temporaries beside `antigravity-oauth-token`.
    pub fn is_codewire_temporary(name: &str) -> bool {
        name.starts_with(&format!(".{ANTIGRAVITY_TOKEN_FILE_NAME}.codewire."))
    }

    /// Whether the temporary `name` is a write in progress (removed unread).
    pub fn is_codewire_write_in_progress(name: &str) -> bool {
        is_codewire_temporary(name) && name.ends_with(".new")
    }

    /// Whether the temporary `name` holding `contents` is Codewire's.
    pub fn is_codewire_leftover(name: &str, contents: &[u8]) -> bool {
        is_codewire_write_in_progress(name)
            || (is_codewire_temporary(name) && is_codewire_token_file(contents))
    }
}
