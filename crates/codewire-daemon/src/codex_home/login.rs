//! Codex's own ChatGPT login in a hosted Sandbox: a listed direct delivery
//! exception (docs/dev/SECRETS-AND-CREDENTIALS.md, "Direct delivery
//! exceptions"). Codex enables `/usage`, analytics and account routing only
//! with its own login and has no hook for a login held elsewhere, so the proxy
//! cannot provide them.
//!
//! While Codex is selected, the hosted daemon asks the broker for the Sandbox
//! creator's personal login when it starts and every two minutes, only on a
//! bridge epoch that lists `codex-login`, and writes it as Codex's standard
//! `~/.codex/auth.json` with [`CODEX_MANAGED_REFRESH_TOKEN`] in place of the
//! refresh token, which never leaves Codewire. A delivered login means Codex
//! uses its built-in provider, so Codewire's proxy `config.toml` is removed;
//! a denied one restores it.
//!
//! The file is Codewire's only while it is a regular file (never a symlink) of
//! the daemon's uid that parses, has `auth_mode` `"chatgpt"` and holds exactly
//! the placeholder refresh token. Anything else, including a file Codex is
//! rewriting in place at that moment, is the user's and is never written,
//! replaced or removed. Every file operation is relative to `~/.codex` opened
//! with `O_NOFOLLOW`; a symlinked `~/.codex` receives nothing. Removal renames
//! the file aside, checks it is still Codewire's and restores it without
//! replacing anything if it is not, so a concurrent `codex login` is never
//! deleted.
//!
//! If Codewire wrote the file and it is gone, the user ran `codex logout`: the
//! daemon records that under the container's `/tmp`, keyed by environment
//! generation and credential, and writes nothing more for that credential
//! until the Sandbox restarts (a new container) or Codex is re-selected (a new
//! generation). A daemon restart keeps it.
//!
//! No token, file content or path is logged: only [`CodexLoginSync`] states.
//! The records, the zeroizing document and the check loop are shared with the
//! Claude login writer ([`crate::agent_login`]).

use std::future::Future;
use std::io;
use std::path::PathBuf;
use std::time::Duration;

use codewire_access::ManagedCredentialClientPlacement;
use codewire_credential_bridge::LoginFailure;
use codewire_workload_secrets::{CodexLogin, CodexLoginBinding, OpenedCodexLogin};
use serde_json::{Map, Value};
use tokio::sync::watch;
use zeroize::{Zeroize as _, Zeroizing};

use super::{CODEX_HOME_MODE, CodexHome};
pub use crate::agent_login::Removal;
use crate::agent_login::{
    Document, LoginOutcome, LoginState, LoginWriter, run_login_writer, scrub, unix_now,
};
#[cfg(test)]
use crate::agent_login::{LOGIN_RETRY_MIN, Retry};
use crate::private_files::{Entry, OwnedEntry, PrivateDirectory, ensure_private_directory};

/// Codex's login file in its home.
pub const CODEX_AUTH_FILE_NAME: &str = "auth.json";
/// The refresh token Codewire writes. It must not be empty: `codex logout`
/// revokes the refresh token, or the access token when the refresh token is
/// empty, and Codewire's access token must stay usable by the creator's other
/// Sandboxes.
pub const CODEX_MANAGED_REFRESH_TOKEN: &str = "codewire-managed-no-refresh-token";
const _: () = assert!(!CODEX_MANAGED_REFRESH_TOKEN.is_empty());
/// Container-local state: a new container (a Sandbox restart) starts empty.
pub const CODEX_LOGIN_STATE_DIRECTORY: &str = "/tmp/codewire-codex-login";
/// How often a delivered login is checked for rotation and revocation, unless
/// the Kind test deployment selects a shorter period
/// ([`crate::config::CODEX_LOGIN_CHECK_PERIOD_ENV`]).
pub use crate::config::CODEX_LOGIN_CHECK_PERIOD;
/// With no delivery for this long while the bridge fails, Codewire's login is
/// removed ([`crate::agent_login::LOGIN_LAPSE`]).
pub const CODEX_LOGIN_LAPSE: Duration = crate::agent_login::LOGIN_LAPSE;
const AUTH_FILE_MODE: u32 = crate::agent_login::PRIVATE_FILE_MODE;
/// Real logins are a few kilobytes; a larger file is never Codewire's.
const MAX_AUTH_BYTES: u64 = 1024 * 1024;

/// What one check did. It names no token, file content or path.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CodexLoginSync {
    /// `auth.json` now holds the delivered login.
    Written,
    /// `auth.json` already held it.
    Current,
    /// The user's own login is present, or `~/.codex` is not a plain directory
    /// of the daemon's uid. Nothing was written.
    UserOwned,
    /// The user ran `codex logout`. Nothing is written for this credential
    /// until the Sandbox restarts or Codex is re-selected.
    LoggedOut,
    /// The delivered login is an older generation of the credential Codewire
    /// last wrote. Nothing was written.
    LowerGeneration,
    /// The delivered ID token is not a JWT Codex can read. Nothing was written.
    Invalid,
    /// The broker denied delivery: Codewire's `auth.json` is removed and its
    /// proxy `config.toml` is back.
    Denied,
    /// No delivery this time (no epoch, or the broker was unavailable).
    /// Nothing changed.
    Unavailable,
    /// The epoch's host does not list `codex-login`; nothing was asked and
    /// nothing changed.
    Unsupported,
    /// Codewire's login had expired and was removed while the bridge failed.
    Expired,
    /// The bridge failed for [`CODEX_LOGIN_LAPSE`] without a delivery, so
    /// Codewire's login was removed.
    Lapsed,
}

/// What the bridge answered one login request.
#[derive(Debug)]
pub enum CodexLoginDelivery {
    Delivered(OpenedCodexLogin),
    Denied,
    Unavailable,
    Unsupported,
}

impl From<Result<OpenedCodexLogin, LoginFailure>> for CodexLoginDelivery {
    fn from(result: Result<OpenedCodexLogin, LoginFailure>) -> Self {
        match result {
            Ok(opened) => Self::Delivered(opened),
            Err(LoginFailure::Denied) => Self::Denied,
            Err(LoginFailure::Unavailable) => Self::Unavailable,
            Err(LoginFailure::Unsupported) => Self::Unsupported,
        }
    }
}

/// The one writer of Codewire's `auth.json` in one hosted container.
#[derive(Debug)]
pub struct CodexLoginWriter {
    home: CodexHome,
    proxy_config: String,
    state: LoginState,
    /// Unix seconds since when no login has been delivered; `None` right
    /// after a delivery or a denial.
    failing_since: Option<u64>,
}

impl CodexLoginWriter {
    /// A writer for `home` that restores `proxy_config` (Codewire's
    /// `config.toml`) whenever no login is delivered. Its logout and last-write
    /// records live in `state_directory` under `generation`. `now_unix` starts
    /// the [`CODEX_LOGIN_LAPSE`] window: no login has been delivered yet.
    pub fn new(
        home: CodexHome,
        proxy_config: String,
        state_directory: impl Into<PathBuf>,
        generation: u64,
        now_unix: u64,
    ) -> Self {
        Self {
            home,
            proxy_config,
            state: LoginState::load(state_directory.into(), generation, "codex"),
            failing_since: Some(now_unix),
        }
    }

    /// Apply one bridge answer at `now_unix` (Unix seconds).
    pub fn apply(
        &mut self,
        delivery: CodexLoginDelivery,
        now_unix: u64,
    ) -> io::Result<CodexLoginSync> {
        match delivery {
            CodexLoginDelivery::Delivered(opened) => self.deliver(opened),
            CodexLoginDelivery::Denied => {
                self.failing_since = None;
                self.withdraw()?;
                Ok(CodexLoginSync::Denied)
            }
            CodexLoginDelivery::Unavailable => self.failing(now_unix, CodexLoginSync::Unavailable),
            CodexLoginDelivery::Unsupported => self.failing(now_unix, CodexLoginSync::Unsupported),
        }
    }

    fn deliver(&mut self, opened: OpenedCodexLogin) -> io::Result<CodexLoginSync> {
        let OpenedCodexLogin { binding, login } = opened;
        if !codex_reads_id_token(login.id_token()) {
            return Ok(CodexLoginSync::Invalid);
        }
        self.failing_since = None;
        let Some(home) = self.home.open_for_login(true)? else {
            return Ok(CodexLoginSync::UserOwned);
        };
        let outcome = self.install(&home, binding, &login)?;
        // A delivered login means Codex uses its built-in provider, whatever
        // `auth.json` holds: the user's own login wins, and a logged-out Codex
        // stays logged out instead of falling back to the proxy.
        self.home.sync_config(None)?;
        Ok(outcome)
    }

    fn install(
        &mut self,
        home: &PrivateDirectory,
        binding: CodexLoginBinding,
        login: &CodexLogin,
    ) -> io::Result<CodexLoginSync> {
        if self.state.is_logged_out(&binding.credential_id) {
            return Ok(CodexLoginSync::LoggedOut);
        }
        match classify(home, CODEX_AUTH_FILE_NAME)? {
            AuthFile::User => Ok(CodexLoginSync::UserOwned),
            AuthFile::Absent => {
                if let Some(written) = self.state.written.clone() {
                    // Codewire wrote a login here and it is gone: the user
                    // ran `codex logout`.
                    self.state.record_logout(&written.credential_id);
                    self.state.forget_written();
                    if self.state.is_logged_out(&binding.credential_id) {
                        return Ok(CodexLoginSync::LoggedOut);
                    }
                }
                let document = login_document(None, login);
                if install_new(home, &document.to_bytes()?)? {
                    self.state.record_written(binding);
                    Ok(CodexLoginSync::Written)
                } else {
                    Ok(CodexLoginSync::UserOwned)
                }
            }
            AuthFile::Codewire { entry, document } => {
                if self
                    .state
                    .written
                    .as_ref()
                    .is_some_and(|written| !binding.may_replace(written))
                {
                    return Ok(CodexLoginSync::LowerGeneration);
                }
                let desired = login_document(document.object(), login);
                if entry.mode == AUTH_FILE_MODE && same_login(&document, &desired) {
                    self.state.record_written(binding);
                    return Ok(CodexLoginSync::Current);
                }
                if replace(home, &entry, &desired.to_bytes()?)? {
                    self.state.record_written(binding);
                    Ok(CodexLoginSync::Written)
                } else {
                    Ok(CodexLoginSync::UserOwned)
                }
            }
        }
    }

    /// No delivery: remove Codewire's login once its access token has expired,
    /// or once the bridge has failed for [`CODEX_LOGIN_LAPSE`].
    fn failing(&mut self, now_unix: u64, outcome: CodexLoginSync) -> io::Result<CodexLoginSync> {
        let since = *self.failing_since.get_or_insert(now_unix);
        let lapsed = now_unix.saturating_sub(since) >= CODEX_LOGIN_LAPSE.as_secs();
        let Some(home) = self.home.open_for_login(false)? else {
            return Ok(outcome);
        };
        let removal = remove(&home, |document| {
            lapsed || access_token_expired(document, now_unix)
        })?;
        if removal != Removal::Removed {
            return Ok(outcome);
        }
        self.state.forget_written();
        self.home.sync_config(Some(&self.proxy_config))?;
        Ok(if lapsed {
            CodexLoginSync::Lapsed
        } else {
            CodexLoginSync::Expired
        })
    }

    /// An explicit denial: remove Codewire's login and restore its proxy
    /// `config.toml` if that is absent or Codewire's.
    fn withdraw(&mut self) -> io::Result<()> {
        if let Some(home) = self.home.open_for_login(false)?
            && remove(&home, |_| true)? == Removal::Removed
        {
            self.state.forget_written();
        }
        self.home.sync_config(Some(&self.proxy_config))?;
        Ok(())
    }
}

impl CodexHome {
    /// `~/.codex` for the login, never through a symlink. `None` when it is a
    /// symlink, not a directory or another uid's, or, unless `create`, absent.
    fn open_for_login(&self, create: bool) -> io::Result<Option<PrivateDirectory>> {
        match PrivateDirectory::open(self.root()) {
            Err(error) if error.kind() == io::ErrorKind::NotFound && create => {
                ensure_private_directory(self.root(), CODEX_HOME_MODE)?;
                PrivateDirectory::open(self.root())
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
            result => result,
        }
    }

    /// Remove Codewire's `auth.json` when Codex is not selected. The user's
    /// own login is never touched.
    pub(crate) fn remove_codewire_login(&self) -> io::Result<Removal> {
        match PrivateDirectory::open(self.root()) {
            Ok(Some(home)) => remove(&home, |_| true),
            Ok(None) => Ok(Removal::Kept),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(Removal::Absent),
            Err(error) => Err(error),
        }
    }

    pub fn auth_path(&self) -> PathBuf {
        self.root().join(CODEX_AUTH_FILE_NAME)
    }
}

enum AuthFile {
    Absent,
    User,
    Codewire {
        entry: OwnedEntry,
        document: Document,
    },
}

/// Classify `name` in `home` without following a symlink.
fn classify(home: &PrivateDirectory, name: &str) -> io::Result<AuthFile> {
    let entry = match home.read(name, MAX_AUTH_BYTES)? {
        Entry::Absent => return Ok(AuthFile::Absent),
        Entry::Foreign => return Ok(AuthFile::User),
        Entry::Owned(entry) => entry,
    };
    Ok(match Document::parse(&entry.contents) {
        Some(document) if document.is_codewire() => AuthFile::Codewire { entry, document },
        _ => AuthFile::User,
    })
}

/// Install a new `auth.json` where there was none. A file that appeared since
/// the inspection is the user's and stays: the rename never replaces.
fn install_new(home: &PrivateDirectory, contents: &[u8]) -> io::Result<bool> {
    home.install_new(
        &temporary_name("new"),
        CODEX_AUTH_FILE_NAME,
        contents,
        AUTH_FILE_MODE,
    )
}

/// Replace Codewire's `auth.json`, compared against the file on disk right
/// before the rename: only the exact file inspected, unchanged, is replaced.
fn replace(home: &PrivateDirectory, inspected: &OwnedEntry, contents: &[u8]) -> io::Result<bool> {
    home.replace_unchanged(
        &temporary_name("new"),
        CODEX_AUTH_FILE_NAME,
        inspected,
        MAX_AUTH_BYTES,
        contents,
        AUTH_FILE_MODE,
    )
}

/// Remove Codewire's `auth.json` when `select` chooses it: rename it aside,
/// check the file moved aside is still Codewire's and still chosen, and
/// restore it without replacing anything if it is not.
fn remove(home: &PrivateDirectory, select: impl Fn(&Document) -> bool) -> io::Result<Removal> {
    match classify(home, CODEX_AUTH_FILE_NAME)? {
        AuthFile::Absent => return Ok(Removal::Absent),
        AuthFile::User => return Ok(Removal::Kept),
        AuthFile::Codewire { document, .. } if !select(&document) => return Ok(Removal::Kept),
        AuthFile::Codewire { .. } => {}
    }
    let aside = temporary_name("aside");
    match home.rename(CODEX_AUTH_FILE_NAME, &aside) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Removal::Absent),
        Err(error) => return Err(error),
    }
    settle_aside(home, &aside, select)
}

/// The second half of [`remove`]: delete the file at `aside` if it is
/// Codewire's and chosen, otherwise put it back as `auth.json` unless a new one
/// appeared, in which case it stays at `aside` rather than being lost.
fn settle_aside(
    home: &PrivateDirectory,
    aside: &str,
    select: impl Fn(&Document) -> bool,
) -> io::Result<Removal> {
    let codewire = match classify(home, aside)? {
        AuthFile::Absent => return Ok(Removal::Absent),
        AuthFile::Codewire { document, .. } => select(&document),
        AuthFile::User => false,
    };
    if codewire {
        home.unlink(aside)?;
        home.sync()?;
        return Ok(Removal::Removed);
    }
    if !home.rename_noreplace(aside, CODEX_AUTH_FILE_NAME)? {
        tracing::warn!(
            "a new Codex auth.json appeared while Codewire checked the previous one; \
             the previous file was kept beside it"
        );
    }
    home.sync()?;
    Ok(Removal::Kept)
}

/// A unique hidden sibling name; [`PrivateDirectory::write_new`] creates it
/// exclusively.
fn temporary_name(purpose: &str) -> String {
    format!(
        ".{CODEX_AUTH_FILE_NAME}.codewire.{}.{purpose}",
        uuid::Uuid::new_v4().simple()
    )
}

/// `auth.json` as Codex writes it.
impl Document {
    fn tokens(&self) -> Option<&Map<String, Value>> {
        self.object()?.get("tokens")?.as_object()
    }

    /// Codewire's: ChatGPT mode with exactly the placeholder refresh token.
    fn is_codewire(&self) -> bool {
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

/// Codex 0.157's standard ChatGPT `auth.json`, keeping every other field of
/// `existing`.
fn login_document(existing: Option<&Map<String, Value>>, login: &CodexLogin) -> Document {
    let mut object = existing.cloned().unwrap_or_default();
    let mut tokens = object
        .remove("tokens")
        .and_then(|tokens| match tokens {
            Value::Object(tokens) => Some(tokens),
            mut other => {
                scrub(&mut other);
                None
            }
        })
        .unwrap_or_default();
    for (key, value) in [
        ("id_token", login.id_token()),
        ("access_token", login.access_token()),
        ("refresh_token", CODEX_MANAGED_REFRESH_TOKEN),
        ("account_id", login.account_id()),
    ] {
        if let Some(mut previous) = tokens.insert(key.to_owned(), Value::String(value.to_owned())) {
            scrub(&mut previous);
        }
    }
    for (key, value) in [
        ("auth_mode", Value::String("chatgpt".to_owned())),
        ("OPENAI_API_KEY", Value::Null),
        ("tokens", Value::Object(tokens)),
        (
            "last_refresh",
            Value::String(rfc3339_utc(login.refreshed_at_unix())),
        ),
    ] {
        if let Some(mut previous) = object.insert(key.to_owned(), value) {
            scrub(&mut previous);
        }
    }
    Document(Value::Object(object))
}

/// Whether `existing` already holds every field `desired` sets.
fn same_login(existing: &Document, desired: &Document) -> bool {
    let (Some(existing), Some(desired)) = (existing.object(), desired.object()) else {
        return false;
    };
    ["auth_mode", "OPENAI_API_KEY", "last_refresh"]
        .iter()
        .all(|key| existing.get(*key) == desired.get(*key))
        && ["id_token", "access_token", "refresh_token", "account_id"]
            .iter()
            .all(|key| token_field(existing, key) == token_field(desired, key))
}

fn token_field<'a>(object: &'a Map<String, Value>, key: &str) -> Option<&'a Value> {
    object.get("tokens")?.as_object()?.get(key)
}

/// Whether Codewire's login's access token has a JWT `exp` at or before
/// `now_unix`. A token without a readable `exp` is not judged expired here.
fn access_token_expired(document: &Document, now_unix: u64) -> bool {
    let Some(token) = document
        .tokens()
        .and_then(|tokens| tokens.get("access_token"))
        .and_then(Value::as_str)
    else {
        return false;
    };
    let Some(claims) = jwt_claims(token) else {
        return false;
    };
    let expiry = claims
        .object()
        .and_then(|claims| claims.get("exp"))
        .and_then(Value::as_i64);
    expiry.is_some_and(|expiry| expiry <= i64::try_from(now_unix).unwrap_or(i64::MAX))
}

/// Codex parses the ID token's claims whenever it loads `auth.json` and
/// refuses the whole file if it cannot. Require what it requires: three
/// non-empty parts, the second base64url JSON.
fn codex_reads_id_token(token: &str) -> bool {
    jwt_claims(token).is_some()
}

/// The claims of a three-part JWT, unverified: Codex reads them the same way.
fn jwt_claims(token: &str) -> Option<Document> {
    let mut parts = token.split('.');
    let (Some(header), Some(payload), Some(signature), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return None;
    };
    if header.is_empty() || payload.is_empty() || signature.is_empty() {
        return None;
    }
    Document::parse(&base64url_decode(payload)?)
}

fn base64url_decode(input: &str) -> Option<Zeroizing<Vec<u8>>> {
    let input = input.as_bytes();
    if input.len() % 4 == 1 {
        return None;
    }
    let mut output = Zeroizing::new(Vec::with_capacity(input.len() * 3 / 4 + 1));
    let mut buffer = 0_u32;
    let mut bits = 0_u32;
    for &byte in input {
        let value = match byte {
            b'A'..=b'Z' => byte - b'A',
            b'a'..=b'z' => byte - b'a' + 26,
            b'0'..=b'9' => byte - b'0' + 52,
            b'-' => 62,
            b'_' => 63,
            _ => return None,
        };
        buffer = (buffer << 6) | u32::from(value);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            output.push((buffer >> bits) as u8);
            buffer &= (1 << bits) - 1;
        }
    }
    buffer.zeroize();
    Some(output)
}

/// `YYYY-MM-DDTHH:MM:SSZ`, as Codex writes `last_refresh`.
fn rfc3339_utc(unix: u64) -> String {
    let days = unix / 86_400;
    let seconds = unix % 86_400;
    // Howard Hinnant's civil_from_days, for days since 1970-01-01.
    let shifted = days as i64 + 719_468;
    let era = shifted.div_euclid(146_097);
    let day_of_era = shifted.rem_euclid(146_097);
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_index = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_index + 2) / 5 + 1;
    let month = if month_index < 10 {
        month_index + 3
    } else {
        month_index - 9
    };
    let year = year_of_era + era * 400 + i64::from(month <= 2);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        seconds / 3_600,
        seconds % 3_600 / 60,
        seconds % 60
    )
}

/// The most leftover temporaries one start removes.
const MAX_LEFTOVERS: usize = 64;

impl CodexLoginWriter {
    /// Remove what an interrupted write or removal left beside `auth.json`,
    /// so no stray copy of a token outlives a crash or a revocation: every
    /// `.auth.json.codewire.*` temporary that is a write in progress (`.new`)
    /// or holds Codewire's login. A file set aside because it was the user's
    /// stays. Returns how many were removed.
    pub fn remove_leftovers(&self) -> io::Result<usize> {
        let Some(home) = self.home.open_for_login(false)? else {
            return Ok(0);
        };
        let prefix = format!(".{CODEX_AUTH_FILE_NAME}.codewire.");
        let mut removed = 0;
        for name in home.names_with_prefix(&prefix, MAX_LEFTOVERS)? {
            let codewire = name.ends_with(".new")
                || matches!(classify(&home, &name)?, AuthFile::Codewire { .. });
            if codewire {
                home.unlink(&name)?;
                removed += 1;
            }
        }
        if removed > 0 {
            home.sync()?;
        }
        Ok(removed)
    }
}

/// The login writer of a hosted daemon serving `config` in `home`, or `None`:
/// only on a hosted bridge, and only while Codex is selected.
pub(crate) fn hosted_writer(config: &crate::Config, home: CodexHome) -> Option<CodexLoginWriter> {
    let bridge = config
        .credential_bridge
        .as_ref()
        .filter(|bridge| bridge.transport == crate::CredentialBridgeTransport::Hosted)?;
    let proxy_config = config
        .managed_credential_clients
        .for_placement(ManagedCredentialClientPlacement::Platform)
        .codex?
        .into_config_toml();
    let writer = CodexLoginWriter::new(
        home,
        proxy_config,
        CODEX_LOGIN_STATE_DIRECTORY,
        bridge.environment_generation,
        unix_now(),
    );
    if let Err(error) = writer.remove_leftovers() {
        tracing::warn!(error_kind = ?error.kind(), "hosted Codex login leftovers could not be removed");
    }
    Some(writer)
}

/// Where the writer gets a login: the shared bridge, or a test double.
pub(crate) trait CodexLoginSource: Send + Sync + 'static {
    fn codex_login(&self) -> impl Future<Output = Result<OpenedCodexLogin, LoginFailure>> + Send;
}

impl CodexLoginSource for codewire_credential_bridge::CredentialBridge {
    fn codex_login(&self) -> impl Future<Output = Result<OpenedCodexLogin, LoginFailure>> + Send {
        codewire_credential_bridge::CredentialBridge::codex_login(self)
    }
}

impl LoginOutcome for CodexLoginSync {
    const FAILED: Self = Self::Unavailable;

    fn retries_soon(self) -> bool {
        matches!(self, Self::Unavailable | Self::Expired | Self::Lapsed)
    }
}

impl LoginWriter for CodexLoginWriter {
    type Delivery = CodexLoginDelivery;
    type Outcome = CodexLoginSync;

    fn apply(&mut self, delivery: CodexLoginDelivery, now_unix: u64) -> io::Result<CodexLoginSync> {
        CodexLoginWriter::apply(self, delivery, now_unix)
    }

    fn checked(outcome: CodexLoginSync) {
        tracing::info!(codex_login = ?outcome, "hosted Codex login checked");
    }

    fn failed(error: &io::Error) {
        tracing::warn!(error_kind = ?error.kind(), "hosted Codex login check failed");
    }

    fn stopped_unexpectedly() {
        tracing::warn!("hosted Codex login check stopped unexpectedly");
    }
}

/// The hosted daemon's login task: check at start, then every
/// `check_period` ([`CODEX_LOGIN_CHECK_PERIOD`] outside Kind), retrying sooner
/// with jittered backoff while no epoch is admitted or the broker is
/// unavailable. Stops when `shutdown` turns true.
pub(crate) async fn run_codex_login_writer(
    writer: CodexLoginWriter,
    source: impl CodexLoginSource,
    check_period: Duration,
    shutdown: watch::Receiver<bool>,
) {
    let ask = || {
        let login = source.codex_login();
        async move { CodexLoginDelivery::from(login.await) }
    };
    run_login_writer(writer, ask, check_period, shutdown).await;
}

#[cfg(test)]
mod tests;
