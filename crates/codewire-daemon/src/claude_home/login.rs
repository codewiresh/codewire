//! Claude Code's own claude.ai login in a hosted Sandbox: a listed direct
//! delivery exception (docs/dev/SECRETS-AND-CREDENTIALS.md, "Direct delivery
//! exceptions"). Claude Code shows `/usage` and its plan only with its own
//! claude.ai login, and those account calls go straight to `api.anthropic.com`
//! whatever `ANTHROPIC_BASE_URL` says, so the proxy cannot answer them.
//!
//! While the Anthropic client is selected in its sign-in form, the hosted
//! daemon asks the broker for the Sandbox creator's personal Claude sign-in
//! when it starts and every two minutes, only on a bridge epoch that lists
//! `claude-login`, and writes it as `claudeAiOauth` in Claude Code's
//! `~/.claude/.credentials.json`. The refresh token never leaves Codewire: the
//! file carries a non-empty placeholder, [`CLAUDE_MANAGED_REFRESH_TOKEN_PREFIX`]
//! and a nonce that changes with every token written, because Claude Code
//! remembers a refused refresh token as dead for the life of its process.
//! Inference still goes through the managed route (`ANTHROPIC_BASE_URL`),
//! where the broker replaces the bearer with the same or a fresher token.
//!
//! Claude Code keeps other state in the same file (MCP logins and more), so
//! only `claudeAiOauth` and the top-level [`CLAUDE_MANAGED_MARKER`] are
//! Codewire's; every other member is read and kept. The file is touched only
//! while it is a regular file (never a symlink) of the daemon's uid holding a
//! JSON object, and its `claudeAiOauth` is Codewire's: it carries the
//! placeholder, or Claude Code cleared it (an empty refresh token beside the
//! marker) after its own refresh was refused. Any other `claudeAiOauth`,
//! including one from `claude /login` in the Sandbox, is the user's own login
//! and wins: it is never written, replaced or removed. Every file operation is
//! relative to `~/.claude` opened with `O_NOFOLLOW`; a symlinked `~/.claude`
//! receives nothing. Writes go through an exclusive temporary file and a
//! rename, and replace only the exact file inspected, unchanged, so Claude
//! Code's own mtime check picks each change up and a concurrent write of
//! Claude Code's is never lost.
//!
//! If Codewire wrote a login and `claudeAiOauth` is gone, the user ran
//! `/logout` (which keeps the marker): the daemon records that under the
//! container's `/tmp`, keyed by environment generation and credential, and
//! writes nothing more for that credential until the Sandbox restarts (a new
//! container) or the sign-in is re-selected (a new generation). A daemon
//! restart keeps it.
//!
//! No token, file content or path is logged: only [`ClaudeLoginSync`] states.

use std::future::Future;
use std::io;
use std::path::{Path, PathBuf};
use std::time::Duration;

use codewire_credential_bridge::LoginFailure;
use codewire_workload_secrets::{ClaudeLogin, CodexLoginBinding, OpenedClaudeLogin};
use serde_json::{Map, Value};
use tokio::sync::watch;

use super::ClaudeHome;
use crate::agent_login::{
    Document, LoginOutcome, LoginState, LoginWriter, PRIVATE_FILE_MODE, Removal, run_login_writer,
    scrub, unix_now,
};
use crate::private_files::{Entry, OwnedEntry, PrivateDirectory};

/// Claude Code's configuration directory in the user's home; managed launches
/// set neither `CLAUDE_CONFIG_DIR` nor `CLAUDE_SECURESTORAGE_CONFIG_DIR`.
pub const CLAUDE_CONFIG_DIR_NAME: &str = ".claude";
/// Claude Code's plaintext credential store on Linux, in that directory.
pub const CLAUDE_CREDENTIALS_FILE_NAME: &str = ".credentials.json";
/// The member Claude Code reads its claude.ai login from.
pub const CLAUDE_LOGIN_KEY: &str = "claudeAiOauth";
/// The top-level member that marks the file as one Codewire wrote a login
/// into. Claude Code's own writes and its `/logout` keep members they do not
/// name, so it survives both.
pub const CLAUDE_MANAGED_MARKER: &str = "codewireManaged";
/// The start of the refresh token Codewire writes. It is never empty: Claude
/// Code reads an empty refresh token as a dead login.
pub const CLAUDE_MANAGED_REFRESH_TOKEN_PREFIX: &str = "codewire-managed-no-refresh-token-";
const _: () = assert!(!CLAUDE_MANAGED_REFRESH_TOKEN_PREFIX.is_empty());
/// Container-local state: a new container (a Sandbox restart) starts empty.
pub const CLAUDE_LOGIN_STATE_DIRECTORY: &str = "/tmp/codewire-claude-login";
/// With no delivery for this long while the bridge fails, Codewire's login is
/// removed ([`crate::agent_login::LOGIN_LAPSE`]).
pub const CLAUDE_LOGIN_LAPSE: Duration = crate::agent_login::LOGIN_LAPSE;
const CLAUDE_CONFIG_DIR_MODE: u32 = 0o700;
const CREDENTIALS_MODE: u32 = PRIVATE_FILE_MODE;
/// Claude Code refuses a larger store, and so does Codewire.
const MAX_CREDENTIALS_BYTES: u64 = 1024 * 1024;
/// The hexadecimal nonce after [`CLAUDE_MANAGED_REFRESH_TOKEN_PREFIX`].
const NONCE_LENGTH: usize = 32;
/// The most leftover temporaries one start removes.
const MAX_LEFTOVERS: usize = 64;

/// What one check did. It names no token, file content or path.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClaudeLoginSync {
    /// `claudeAiOauth` now holds the delivered login.
    Written,
    /// `claudeAiOauth` already held it.
    Current,
    /// The user's own login is present, the file is not a JSON object of the
    /// daemon's uid, or `~/.claude` is not a plain directory of the daemon's
    /// uid. Nothing was written.
    UserOwned,
    /// The user ran `/logout`. Nothing is written for this credential until
    /// the Sandbox restarts or the sign-in is re-selected.
    LoggedOut,
    /// The delivered login is an older generation of the credential Codewire
    /// last wrote. Nothing was written.
    LowerGeneration,
    /// The delivered access token had already expired. Nothing was written.
    Invalid,
    /// The broker denied delivery: Codewire's `claudeAiOauth` is removed.
    Denied,
    /// No delivery this time (no epoch, or the broker was unavailable).
    /// Nothing changed.
    Unavailable,
    /// The epoch's host does not list `claude-login`; nothing was asked and
    /// nothing changed.
    Unsupported,
    /// Codewire's login had expired and was removed while the bridge failed.
    Expired,
    /// The bridge failed for [`CLAUDE_LOGIN_LAPSE`] without a delivery, so
    /// Codewire's login was removed.
    Lapsed,
}

/// What the bridge answered one login request.
#[derive(Debug)]
pub enum ClaudeLoginDelivery {
    Delivered(OpenedClaudeLogin),
    Denied,
    Unavailable,
    Unsupported,
}

impl From<Result<OpenedClaudeLogin, LoginFailure>> for ClaudeLoginDelivery {
    fn from(result: Result<OpenedClaudeLogin, LoginFailure>) -> Self {
        match result {
            Ok(opened) => Self::Delivered(opened),
            Err(LoginFailure::Denied) => Self::Denied,
            Err(LoginFailure::Unavailable) => Self::Unavailable,
            Err(LoginFailure::Unsupported) => Self::Unsupported,
        }
    }
}

/// The one writer of Codewire's `claudeAiOauth` in one hosted container.
#[derive(Debug)]
pub struct ClaudeLoginWriter {
    /// The workspace user's home, which holds `~/.claude`.
    home: PathBuf,
    state: LoginState,
    /// Unix seconds since when no login has been delivered; `None` right
    /// after a delivery or a denial.
    failing_since: Option<u64>,
}

impl ClaudeLoginWriter {
    /// A writer for `~/.claude` in the home `home`. Its logout and last-write
    /// records live in `state_directory` under `generation`. `now_unix` starts
    /// the [`CLAUDE_LOGIN_LAPSE`] window: no login has been delivered yet.
    pub fn new(
        home: impl Into<PathBuf>,
        state_directory: impl Into<PathBuf>,
        generation: u64,
        now_unix: u64,
    ) -> Self {
        Self {
            home: home.into(),
            state: LoginState::load(state_directory.into(), generation, "claude"),
            failing_since: Some(now_unix),
        }
    }

    /// Remove what an interrupted write or removal left beside the store, so
    /// no stray copy of a token outlives a crash or a revocation: every
    /// `.credentials.json.codewire.*` temporary that is a write in progress
    /// (`.new`) or holds Codewire's login. A store set aside because it was
    /// the user's stays. Returns how many were removed.
    pub fn remove_leftovers(&self) -> io::Result<usize> {
        let Some(config) = open_config(&self.home, false)? else {
            return Ok(0);
        };
        let prefix = format!("{CLAUDE_CREDENTIALS_FILE_NAME}.codewire.");
        let mut removed = 0;
        for name in config.names_with_prefix(&prefix, MAX_LEFTOVERS)? {
            let codewire = name.ends_with(".new")
                || matches!(
                    classify(&config, &name)?,
                    Credentials::Owned {
                        login: OwnLogin::Codewire | OwnLogin::Cleared,
                        ..
                    }
                );
            if codewire {
                config.unlink(&name)?;
                removed += 1;
            }
        }
        if removed > 0 {
            config.sync()?;
        }
        Ok(removed)
    }

    /// Apply one bridge answer at `now_unix` (Unix seconds).
    pub fn apply(
        &mut self,
        delivery: ClaudeLoginDelivery,
        now_unix: u64,
    ) -> io::Result<ClaudeLoginSync> {
        match delivery {
            ClaudeLoginDelivery::Delivered(opened) => self.deliver(opened, now_unix),
            ClaudeLoginDelivery::Denied => {
                self.failing_since = None;
                if let Some(config) = open_config(&self.home, false)?
                    && remove(&config, |_| true)? == Removal::Removed
                {
                    self.state.forget_written();
                }
                Ok(ClaudeLoginSync::Denied)
            }
            ClaudeLoginDelivery::Unavailable => {
                self.failing(now_unix, ClaudeLoginSync::Unavailable)
            }
            ClaudeLoginDelivery::Unsupported => {
                self.failing(now_unix, ClaudeLoginSync::Unsupported)
            }
        }
    }

    fn deliver(&mut self, opened: OpenedClaudeLogin, now_unix: u64) -> io::Result<ClaudeLoginSync> {
        let OpenedClaudeLogin { binding, login } = opened;
        if login.expires_at_unix_ms() <= now_unix.saturating_mul(1_000) {
            return Ok(ClaudeLoginSync::Invalid);
        }
        self.failing_since = None;
        if self.state.is_logged_out(&binding.credential_id) {
            return Ok(ClaudeLoginSync::LoggedOut);
        }
        let Some(config) = open_config(&self.home, true)? else {
            return Ok(ClaudeLoginSync::UserOwned);
        };
        self.install(&config, binding, &login)
    }

    fn install(
        &mut self,
        config: &PrivateDirectory,
        binding: CodexLoginBinding,
        login: &ClaudeLogin,
    ) -> io::Result<ClaudeLoginSync> {
        let (inspected, document) = match classify(config, CLAUDE_CREDENTIALS_FILE_NAME)? {
            Credentials::User => return Ok(ClaudeLoginSync::UserOwned),
            Credentials::Absent => (None, None),
            Credentials::Owned {
                entry,
                document,
                login: OwnLogin::Absent,
            } => (Some(entry), Some(document)),
            Credentials::Owned {
                entry, document, ..
            } => {
                if self
                    .state
                    .written
                    .as_ref()
                    .is_some_and(|written| !binding.may_replace(written))
                {
                    return Ok(ClaudeLoginSync::LowerGeneration);
                }
                if entry.mode == CREDENTIALS_MODE && same_login(&document, login) {
                    self.state.record_written(binding);
                    return Ok(ClaudeLoginSync::Current);
                }
                let desired = login_document(document.object(), login);
                return if replace(config, &entry, &desired.to_bytes()?)? {
                    self.state.record_written(binding);
                    Ok(ClaudeLoginSync::Written)
                } else {
                    Ok(ClaudeLoginSync::UserOwned)
                };
            }
        };
        // No login in the file. If Codewire wrote one here, the user ran
        // `/logout` (or removed the file).
        if let Some(written) = self.state.written.clone() {
            self.state.record_logout(&written.credential_id);
            self.state.forget_written();
            if self.state.is_logged_out(&binding.credential_id) {
                return Ok(ClaudeLoginSync::LoggedOut);
            }
        }
        let desired = login_document(document.as_ref().and_then(Document::object), login);
        let written = match &inspected {
            None => install_new(config, &desired.to_bytes()?)?,
            Some(entry) => replace(config, entry, &desired.to_bytes()?)?,
        };
        if written {
            self.state.record_written(binding);
            Ok(ClaudeLoginSync::Written)
        } else {
            Ok(ClaudeLoginSync::UserOwned)
        }
    }

    /// No delivery: remove Codewire's login once its access token has expired,
    /// or once the bridge has failed for [`CLAUDE_LOGIN_LAPSE`].
    fn failing(&mut self, now_unix: u64, outcome: ClaudeLoginSync) -> io::Result<ClaudeLoginSync> {
        let since = *self.failing_since.get_or_insert(now_unix);
        let lapsed = now_unix.saturating_sub(since) >= CLAUDE_LOGIN_LAPSE.as_secs();
        let Some(config) = open_config(&self.home, false)? else {
            return Ok(outcome);
        };
        let removal = remove(&config, |oauth| lapsed || expired(oauth, now_unix))?;
        if removal != Removal::Removed {
            return Ok(outcome);
        }
        self.state.forget_written();
        Ok(if lapsed {
            ClaudeLoginSync::Lapsed
        } else {
            ClaudeLoginSync::Expired
        })
    }
}

impl ClaudeHome {
    /// Remove Codewire's `claudeAiOauth` when the sign-in form is not
    /// selected. The user's own login and every other member are kept.
    pub(crate) fn remove_codewire_login(&self) -> io::Result<Removal> {
        match open_config(self.root(), false)? {
            Some(config) => remove(&config, |_| true),
            None => Ok(Removal::Absent),
        }
    }

    pub fn credentials_path(&self) -> PathBuf {
        self.root()
            .join(CLAUDE_CONFIG_DIR_NAME)
            .join(CLAUDE_CREDENTIALS_FILE_NAME)
    }
}

/// `~/.claude` in `home`, never through a symlink. `None` when the home or
/// `~/.claude` is a symlink, not a directory or another unprivileged uid's,
/// or, unless `create`, absent.
fn open_config(home: &Path, create: bool) -> io::Result<Option<PrivateDirectory>> {
    let home = match PrivateDirectory::open_home(home) {
        Ok(Some(home)) => home,
        Ok(None) => return Ok(None),
        Err(error) if error.kind() == io::ErrorKind::NotFound && !create => return Ok(None),
        Err(error) => return Err(error),
    };
    if create {
        return home.open_or_create_child(CLAUDE_CONFIG_DIR_NAME, CLAUDE_CONFIG_DIR_MODE);
    }
    match home.open_child(CLAUDE_CONFIG_DIR_NAME) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        result => result,
    }
}

/// What `claudeAiOauth` in a file Codewire may write is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum OwnLogin {
    /// No `claudeAiOauth`.
    Absent,
    /// Codewire's: it carries the placeholder refresh token.
    Codewire,
    /// Codewire's, cleared by Claude Code after its refresh was refused: an
    /// empty refresh token beside the marker.
    Cleared,
}

enum Credentials {
    Absent,
    /// Not a regular JSON-object file of the daemon's uid, or the user's own
    /// login.
    User,
    Owned {
        entry: OwnedEntry,
        document: Document,
        login: OwnLogin,
    },
}

/// Classify `name` in `~/.claude` without following a symlink.
///
/// A login whose refresh token is empty beside the marker counts as
/// Codewire's cleared copy. That is also what a member's own `claude /login`
/// looks like if Claude Code later cleared it after its own refresh was
/// refused while a marker from an earlier delivery remained; such a dead login
/// is replaced by the next delivery, which is the outcome the member gets from
/// signing in again anyway.
fn classify(config: &PrivateDirectory, name: &str) -> io::Result<Credentials> {
    let entry = match config.read(name, MAX_CREDENTIALS_BYTES)? {
        Entry::Absent => return Ok(Credentials::Absent),
        Entry::Foreign => return Ok(Credentials::User),
        Entry::Owned(entry) => entry,
    };
    let Some(document) = Document::parse(&entry.contents) else {
        return Ok(Credentials::User);
    };
    let login = match document.login() {
        None if document.has_login_key() => return Ok(Credentials::User),
        None => OwnLogin::Absent,
        Some(oauth) => match oauth.get("refreshToken").and_then(Value::as_str) {
            Some(token) if is_placeholder(token) => OwnLogin::Codewire,
            Some("") if document.marked() => OwnLogin::Cleared,
            _ => return Ok(Credentials::User),
        },
    };
    Ok(Credentials::Owned {
        entry,
        document,
        login,
    })
}

/// Claude Code's credential store.
impl Document {
    /// `claudeAiOauth`, when it is an object.
    fn login(&self) -> Option<&Map<String, Value>> {
        self.object()?.get(CLAUDE_LOGIN_KEY)?.as_object()
    }

    fn has_login_key(&self) -> bool {
        self.object()
            .is_some_and(|object| object.contains_key(CLAUDE_LOGIN_KEY))
    }

    fn marked(&self) -> bool {
        self.object()
            .and_then(|object| object.get(CLAUDE_MANAGED_MARKER))
            .and_then(Value::as_u64)
            == Some(1)
    }
}

/// Whether `token` is a refresh token Codewire wrote.
fn is_placeholder(token: &str) -> bool {
    token
        .strip_prefix(CLAUDE_MANAGED_REFRESH_TOKEN_PREFIX)
        .is_some_and(|nonce| {
            nonce.len() == NONCE_LENGTH
                && nonce
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        })
}

/// A fresh placeholder refresh token.
fn placeholder() -> String {
    format!(
        "{CLAUDE_MANAGED_REFRESH_TOKEN_PREFIX}{}",
        uuid::Uuid::new_v4().simple()
    )
}

/// The members of `claudeAiOauth` Codewire writes, besides the refresh
/// token, for `login`.
fn login_fields(login: &ClaudeLogin) -> Vec<(&'static str, Value)> {
    let mut fields = vec![
        (
            "accessToken",
            Value::String(login.access_token().to_owned()),
        ),
        ("expiresAt", Value::from(login.expires_at_unix_ms())),
        (
            "scopes",
            Value::Array(
                login
                    .scopes()
                    .iter()
                    .map(|scope| Value::String(scope.clone()))
                    .collect(),
            ),
        ),
    ];
    if let Some(plan) = login.subscription_type() {
        fields.push(("subscriptionType", Value::String(plan.to_owned())));
    }
    if let Some(tier) = login.rate_limit_tier() {
        fields.push(("rateLimitTier", Value::String(tier.to_owned())));
    }
    fields
}

/// `existing` with `claudeAiOauth` holding `login` and a fresh placeholder
/// refresh token, and the marker. Every other member is kept.
fn login_document(existing: Option<&Map<String, Value>>, login: &ClaudeLogin) -> Document {
    let mut object = existing.cloned().unwrap_or_default();
    let mut oauth: Map<String, Value> = login_fields(login)
        .into_iter()
        .map(|(key, value)| (key.to_owned(), value))
        .collect();
    oauth.insert("refreshToken".to_owned(), Value::String(placeholder()));
    for (key, value) in [
        (CLAUDE_LOGIN_KEY, Value::Object(oauth)),
        (CLAUDE_MANAGED_MARKER, Value::from(1)),
    ] {
        if let Some(mut previous) = object.insert(key.to_owned(), value) {
            scrub(&mut previous);
        }
    }
    Document(Value::Object(object))
}

/// Whether Codewire's `claudeAiOauth` in `existing` already holds `login`
/// exactly, with a placeholder refresh token and the marker beside it.
fn same_login(existing: &Document, login: &ClaudeLogin) -> bool {
    let Some(oauth) = existing.login() else {
        return false;
    };
    let mut fields = login_fields(login);
    let current = existing.marked()
        && oauth
            .get("refreshToken")
            .and_then(Value::as_str)
            .is_some_and(is_placeholder)
        && oauth.len() == fields.len() + 1
        && fields
            .iter()
            .all(|(key, value)| oauth.get(*key) == Some(value));
    for (_, value) in &mut fields {
        scrub(value);
    }
    current
}

/// Whether Codewire's login's `expiresAt` (milliseconds) is at or before
/// `now_unix`. A login without a readable expiry is not judged expired here;
/// Claude Code's cleared copy has `expiresAt` 0.
fn expired(oauth: &Map<String, Value>, now_unix: u64) -> bool {
    oauth
        .get("expiresAt")
        .and_then(Value::as_u64)
        .is_some_and(|expires_at| expires_at <= now_unix.saturating_mul(1_000))
}

/// Install a new store where there was none. A file that appeared since the
/// inspection is Claude Code's or the user's and stays: the rename never
/// replaces.
fn install_new(config: &PrivateDirectory, contents: &[u8]) -> io::Result<bool> {
    config.install_new(
        &temporary_name("new"),
        CLAUDE_CREDENTIALS_FILE_NAME,
        contents,
        CREDENTIALS_MODE,
    )
}

/// Replace the store, compared against the file on disk right before the
/// rename: only the exact file inspected, unchanged, is replaced.
fn replace(config: &PrivateDirectory, inspected: &OwnedEntry, contents: &[u8]) -> io::Result<bool> {
    config.replace_unchanged(
        &temporary_name("new"),
        CLAUDE_CREDENTIALS_FILE_NAME,
        inspected,
        MAX_CREDENTIALS_BYTES,
        contents,
        CREDENTIALS_MODE,
    )
}

/// The store without Codewire's members, or `None` when nothing else is in
/// it.
fn without_login(document: &Document) -> Option<Document> {
    let mut object = document.object()?.clone();
    for key in [CLAUDE_LOGIN_KEY, CLAUDE_MANAGED_MARKER] {
        if let Some(mut previous) = object.remove(key) {
            scrub(&mut previous);
        }
    }
    if object.is_empty() {
        return None;
    }
    Some(Document(Value::Object(object)))
}

/// Remove Codewire's `claudeAiOauth` when `select` chooses it, keeping every
/// other member. A store that holds nothing else is renamed aside, checked
/// again and only then deleted, as the Codex writer removes its file.
fn remove(
    config: &PrivateDirectory,
    select: impl Fn(&Map<String, Value>) -> bool,
) -> io::Result<Removal> {
    let (entry, document) = match classify(config, CLAUDE_CREDENTIALS_FILE_NAME)? {
        Credentials::Absent
        | Credentials::Owned {
            login: OwnLogin::Absent,
            ..
        } => return Ok(Removal::Absent),
        Credentials::User => return Ok(Removal::Kept),
        Credentials::Owned {
            entry, document, ..
        } => (entry, document),
    };
    if !document.login().is_some_and(&select) {
        return Ok(Removal::Kept);
    }
    if let Some(remaining) = without_login(&document) {
        return Ok(if replace(config, &entry, &remaining.to_bytes()?)? {
            Removal::Removed
        } else {
            Removal::Kept
        });
    }
    let aside = temporary_name("aside");
    match config.rename(CLAUDE_CREDENTIALS_FILE_NAME, &aside) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Removal::Absent),
        Err(error) => return Err(error),
    }
    settle_aside(config, &aside, select)
}

/// The second half of [`remove`]: delete the file at `aside` if it holds
/// only Codewire's chosen login, otherwise put it back unless a new store
/// appeared, in which case it stays at `aside` rather than being lost.
fn settle_aside(
    config: &PrivateDirectory,
    aside: &str,
    select: impl Fn(&Map<String, Value>) -> bool,
) -> io::Result<Removal> {
    let codewire = match classify(config, aside)? {
        Credentials::Absent => return Ok(Removal::Absent),
        Credentials::Owned {
            document,
            login: OwnLogin::Codewire | OwnLogin::Cleared,
            ..
        } => document.login().is_some_and(&select) && without_login(&document).is_none(),
        Credentials::Owned { .. } | Credentials::User => false,
    };
    if codewire {
        config.unlink(aside)?;
        config.sync()?;
        return Ok(Removal::Removed);
    }
    if !config.rename_noreplace(aside, CLAUDE_CREDENTIALS_FILE_NAME)? {
        tracing::warn!(
            "a new Claude Code credential store appeared while Codewire checked the previous \
             one; the previous file was kept beside it"
        );
    }
    config.sync()?;
    Ok(Removal::Kept)
}

/// A unique hidden sibling name; [`PrivateDirectory::write_new`] creates it
/// exclusively.
fn temporary_name(purpose: &str) -> String {
    format!(
        "{CLAUDE_CREDENTIALS_FILE_NAME}.codewire.{}.{purpose}",
        uuid::Uuid::new_v4().simple()
    )
}

/// The login writer of a hosted daemon serving `config`, or `None`: only on a
/// hosted bridge, and only while the Anthropic client is selected in its
/// sign-in form.
pub(crate) fn hosted_writer(config: &crate::Config) -> Option<ClaudeLoginWriter> {
    let bridge = config
        .credential_bridge
        .as_ref()
        .filter(|bridge| bridge.transport == crate::CredentialBridgeTransport::Hosted)?;
    if !config.managed_credential_clients.anthropic_sign_in() {
        return None;
    }
    let writer = ClaudeLoginWriter::new(
        &config.home_root,
        CLAUDE_LOGIN_STATE_DIRECTORY,
        bridge.environment_generation,
        unix_now(),
    );
    if let Err(error) = writer.remove_leftovers() {
        tracing::warn!(error_kind = ?error.kind(), "hosted Claude login leftovers could not be removed");
    }
    Some(writer)
}

/// Where the writer gets a login: the shared bridge, or a test double.
pub(crate) trait ClaudeLoginSource: Send + Sync + 'static {
    fn claude_login(&self) -> impl Future<Output = Result<OpenedClaudeLogin, LoginFailure>> + Send;
}

impl ClaudeLoginSource for codewire_credential_bridge::CredentialBridge {
    fn claude_login(&self) -> impl Future<Output = Result<OpenedClaudeLogin, LoginFailure>> + Send {
        codewire_credential_bridge::CredentialBridge::claude_login(self)
    }
}

impl LoginOutcome for ClaudeLoginSync {
    const FAILED: Self = Self::Unavailable;

    fn retries_soon(self) -> bool {
        matches!(self, Self::Unavailable | Self::Expired | Self::Lapsed)
    }
}

impl LoginWriter for ClaudeLoginWriter {
    type Delivery = ClaudeLoginDelivery;
    type Outcome = ClaudeLoginSync;

    fn apply(
        &mut self,
        delivery: ClaudeLoginDelivery,
        now_unix: u64,
    ) -> io::Result<ClaudeLoginSync> {
        ClaudeLoginWriter::apply(self, delivery, now_unix)
    }

    fn checked(outcome: ClaudeLoginSync) {
        tracing::info!(claude_login = ?outcome, "hosted Claude login checked");
    }

    fn failed(error: &io::Error) {
        tracing::warn!(error_kind = ?error.kind(), "hosted Claude login check failed");
    }

    fn stopped_unexpectedly() {
        tracing::warn!("hosted Claude login check stopped unexpectedly");
    }
}

/// The hosted daemon's Claude login task, with the Codex login's cadence:
/// check at start, then every `check_period`
/// ([`crate::config::CODEX_LOGIN_CHECK_PERIOD`] outside Kind), retrying
/// sooner with jittered backoff while nothing is delivered. Stops when
/// `shutdown` turns true.
pub(crate) async fn run_claude_login_writer(
    writer: ClaudeLoginWriter,
    source: impl ClaudeLoginSource,
    check_period: Duration,
    shutdown: watch::Receiver<bool>,
) {
    let ask = || {
        let login = source.claude_login();
        async move { ClaudeLoginDelivery::from(login.await) }
    };
    run_login_writer(writer, ask, check_period, shutdown).await;
}

#[cfg(test)]
mod tests;
