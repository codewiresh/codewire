//! Antigravity CLI's placeholder-backed login file
//! (`~/.gemini/antigravity-cli/antigravity-oauth-token`) (#6555).
//!
//! Real Google OAuth tokens NEVER leave the broker: this writer operates ONLY
//! on an intercepted boot and writes ONLY the environment's `cwp1_`
//! placeholder beside the public managed refresh marker
//! (`ANTIGRAVITY_MANAGED_REFRESH_TOKEN`) and far-future expiry
//! (`2099-01-01T00:00:00Z`).
//!
//! Every file operation is relative to `~/.gemini/antigravity-cli` opened with
//! `O_NOFOLLOW` and uid ownership verification at every directory level. A
//! symlinked home, `.gemini`, `antigravity-cli`, or token file receives
//! nothing. Any user-owned token file (one without Codewire's managed refresh
//! marker) is left untouched.

use std::future::Future;
use std::io;
use std::path::{Path, PathBuf};
use std::time::Duration;

use codewire_credential_bridge::LoginFailure;
use codewire_workload_secrets::{AntigravityLogin, CodexLoginBinding, OpenedAntigravityLogin};
use serde_json::{Map, Value};
use tokio::sync::watch;

use crate::agent_login::{
    Document, LoginOutcome, LoginState, LoginWriter, PRIVATE_FILE_MODE, Removal, run_login_writer,
    unix_now,
};
use crate::delivered_logins::antigravity::codewire_document;
pub use crate::delivered_logins::antigravity::{
    ANTIGRAVITY_CONFIG_DIR_NAME, ANTIGRAVITY_CONFIG_PARENT_DIR, ANTIGRAVITY_MANAGED_REFRESH_TOKEN,
    ANTIGRAVITY_TOKEN_FILE_NAME, is_codewire_leftover, is_codewire_temporary,
    is_codewire_token_file, is_codewire_write_in_progress,
};
use crate::private_files::{Entry, FileOwner, OwnedEntry, PrivateDirectory};

/// Container-local state: a new container starts empty.
pub const ANTIGRAVITY_LOGIN_STATE_DIRECTORY: &str = "/tmp/codewire-antigravity-login";
pub const ANTIGRAVITY_LOGIN_LAPSE: Duration = crate::agent_login::LOGIN_LAPSE;
const CONFIG_DIR_MODE: u32 = 0o700;
const TOKEN_FILE_MODE: u32 = PRIVATE_FILE_MODE;
const MAX_TOKEN_BYTES: u64 = 1024 * 1024;
const MAX_LEFTOVERS: usize = 64;
const MANAGED_EXPIRY_RFC3339: &str = "2099-01-01T00:00:00Z";

/// One home's Antigravity CLI token path and optional file owner.
#[derive(Clone, Debug)]
pub struct AntigravityHome {
    root: PathBuf,
    owner: Option<FileOwner>,
}

impl AntigravityHome {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self {
            root: root.into(),
            owner: None,
        }
    }

    pub fn for_owner(mut self, owner: FileOwner) -> Self {
        self.owner = Some(owner);
        self
    }

    pub fn token_path(&self) -> PathBuf {
        self.root
            .join(ANTIGRAVITY_CONFIG_PARENT_DIR)
            .join(ANTIGRAVITY_CONFIG_DIR_NAME)
            .join(ANTIGRAVITY_TOKEN_FILE_NAME)
    }

    /// Remove Codewire's managed Antigravity token file, leaving any user-owned
    /// token file untouched.
    pub(crate) fn remove_codewire_login(&self) -> io::Result<Removal> {
        match open_config(&self.root, false, self.owner)? {
            Some(config) => remove(&config),
            None => Ok(Removal::Absent),
        }
    }
}

/// What one check did. Names no token, placeholder, email, or path.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AntigravityLoginSync {
    Written,
    Current,
    UserOwned,
    LoggedOut,
    LowerGeneration,
    NotPlaceholder,
    NotIntercepted,
    Denied,
    Unavailable,
    Unsupported,
    Lapsed,
}

#[derive(Debug)]
pub enum AntigravityLoginDelivery {
    Delivered(OpenedAntigravityLogin),
    Denied,
    Unavailable,
    Unsupported,
}

impl From<Result<OpenedAntigravityLogin, LoginFailure>> for AntigravityLoginDelivery {
    fn from(result: Result<OpenedAntigravityLogin, LoginFailure>) -> Self {
        match result {
            Ok(opened) => Self::Delivered(opened),
            Err(LoginFailure::Denied) => Self::Denied,
            Err(LoginFailure::Unavailable) => Self::Unavailable,
            Err(LoginFailure::Unsupported) => Self::Unsupported,
        }
    }
}

/// The one writer of Codewire's `antigravity-oauth-token` in a container or VM.
#[derive(Debug)]
pub struct AntigravityLoginWriter {
    home: PathBuf,
    owner: Option<FileOwner>,
    state: LoginState,
    failing_since: Option<u64>,
    intercepting: bool,
}

impl AntigravityLoginWriter {
    pub fn new(
        home: impl Into<PathBuf>,
        state_directory: impl Into<PathBuf>,
        generation: u64,
        now_unix: u64,
    ) -> Self {
        Self {
            home: home.into(),
            owner: None,
            state: LoginState::load(state_directory.into(), generation, "antigravity"),
            failing_since: Some(now_unix),
            intercepting: false,
        }
    }

    pub fn intercepting(mut self) -> Self {
        self.intercepting = true;
        self
    }

    pub fn for_owner(mut self, owner: FileOwner) -> Self {
        self.owner = Some(owner);
        self
    }

    /// Remove any leftover Codewire temporary files beside the token file.
    pub fn remove_leftovers(&self) -> io::Result<usize> {
        let Some(config) = open_config(&self.home, false, self.owner)? else {
            return Ok(0);
        };
        let prefix = format!(".{ANTIGRAVITY_TOKEN_FILE_NAME}.codewire.");
        let mut removed = 0;
        for name in config.names_with_prefix(&prefix, MAX_LEFTOVERS)? {
            let codewire = is_codewire_write_in_progress(&name)
                || matches!(classify(&config, &name)?, TokenFile::Codewire { .. });
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

    pub fn apply(
        &mut self,
        delivery: AntigravityLoginDelivery,
        now_unix: u64,
    ) -> io::Result<AntigravityLoginSync> {
        match delivery {
            AntigravityLoginDelivery::Delivered(opened) => self.deliver(opened),
            AntigravityLoginDelivery::Denied => {
                self.failing_since = None;
                self.clear_codewire()?;
                Ok(AntigravityLoginSync::Denied)
            }
            AntigravityLoginDelivery::Unavailable => {
                self.failing(now_unix, AntigravityLoginSync::Unavailable)
            }
            AntigravityLoginDelivery::Unsupported => {
                self.failing(now_unix, AntigravityLoginSync::Unsupported)
            }
        }
    }

    fn clear_codewire(&mut self) -> io::Result<()> {
        if let Some(config) = open_config(&self.home, false, self.owner)?
            && remove(&config)? == Removal::Removed
        {
            self.state.forget_written();
        }
        Ok(())
    }

    fn deliver(&mut self, opened: OpenedAntigravityLogin) -> io::Result<AntigravityLoginSync> {
        let OpenedAntigravityLogin { binding, login } = opened;
        self.failing_since = None;
        if !self.intercepting {
            self.clear_codewire()?;
            return Ok(AntigravityLoginSync::NotIntercepted);
        }
        if !codewire_access::CredentialPlaceholder::looks_like(login.placeholder()) {
            self.clear_codewire()?;
            return Ok(AntigravityLoginSync::NotPlaceholder);
        }
        if self.state.is_logged_out(&binding.credential_id) {
            return Ok(AntigravityLoginSync::LoggedOut);
        }
        let Some(config) = open_config(&self.home, true, self.owner)? else {
            return Ok(AntigravityLoginSync::UserOwned);
        };
        self.install(&config, binding, &login)
    }

    fn install(
        &mut self,
        config: &PrivateDirectory,
        binding: CodexLoginBinding,
        login: &AntigravityLogin,
    ) -> io::Result<AntigravityLoginSync> {
        let desired = login_document(login);
        match classify(config, ANTIGRAVITY_TOKEN_FILE_NAME)? {
            TokenFile::User => Ok(AntigravityLoginSync::UserOwned),
            TokenFile::Absent => {
                if let Some(written) = self.state.written.clone() {
                    self.state.record_logout(&written.credential_id);
                    self.state.forget_written();
                    if self.state.is_logged_out(&binding.credential_id) {
                        return Ok(AntigravityLoginSync::LoggedOut);
                    }
                }
                if install_new(config, &desired.to_bytes()?)? {
                    self.state.record_written(binding);
                    Ok(AntigravityLoginSync::Written)
                } else {
                    Ok(AntigravityLoginSync::UserOwned)
                }
            }
            TokenFile::Codewire { entry, document } => {
                if self
                    .state
                    .written
                    .as_ref()
                    .is_some_and(|written| !binding.may_replace(written))
                {
                    return Ok(AntigravityLoginSync::LowerGeneration);
                }
                if entry.mode == TOKEN_FILE_MODE && same_login(&document, login) {
                    self.state.record_written(binding);
                    return Ok(AntigravityLoginSync::Current);
                }
                if replace(config, &entry, &desired.to_bytes()?)? {
                    self.state.record_written(binding);
                    Ok(AntigravityLoginSync::Written)
                } else {
                    Ok(AntigravityLoginSync::UserOwned)
                }
            }
        }
    }

    fn failing(
        &mut self,
        now_unix: u64,
        outcome: AntigravityLoginSync,
    ) -> io::Result<AntigravityLoginSync> {
        let since = *self.failing_since.get_or_insert(now_unix);
        if now_unix.saturating_sub(since) < ANTIGRAVITY_LOGIN_LAPSE.as_secs() {
            return Ok(outcome);
        }
        if let Some(config) = open_config(&self.home, false, self.owner)?
            && remove(&config)? == Removal::Removed
        {
            self.state.forget_written();
            return Ok(AntigravityLoginSync::Lapsed);
        }
        Ok(outcome)
    }
}

/// Open `~/.gemini/antigravity-cli` without following any symlink at any level.
fn open_config(
    home: &Path,
    create: bool,
    owner: Option<FileOwner>,
) -> io::Result<Option<PrivateDirectory>> {
    let opened = match owner {
        Some(owner) => PrivateDirectory::open_for(home, owner),
        None => PrivateDirectory::open_home(home),
    };
    let home_dir = match opened {
        Ok(Some(dir)) => dir,
        Ok(None) => return Ok(None),
        Err(error) if error.kind() == io::ErrorKind::NotFound && !create => return Ok(None),
        Err(error) => return Err(error),
    };
    let gemini_dir = if create {
        match home_dir.open_or_create_child(ANTIGRAVITY_CONFIG_PARENT_DIR, CONFIG_DIR_MODE)? {
            Some(dir) => dir,
            None => return Ok(None),
        }
    } else {
        match home_dir.open_child(ANTIGRAVITY_CONFIG_PARENT_DIR) {
            Ok(Some(dir)) => dir,
            Ok(None) => return Ok(None),
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error),
        }
    };
    if create {
        return gemini_dir.open_or_create_child(ANTIGRAVITY_CONFIG_DIR_NAME, CONFIG_DIR_MODE);
    }
    match gemini_dir.open_child(ANTIGRAVITY_CONFIG_DIR_NAME) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        result => result,
    }
}

enum TokenFile {
    Absent,
    User,
    Codewire {
        entry: OwnedEntry,
        document: Document,
    },
}

fn classify(config: &PrivateDirectory, name: &str) -> io::Result<TokenFile> {
    let entry = match config.read(name, MAX_TOKEN_BYTES)? {
        Entry::Absent => return Ok(TokenFile::Absent),
        Entry::Foreign => return Ok(TokenFile::User),
        Entry::Owned(entry) => entry,
    };
    Ok(match codewire_document(&entry.contents) {
        Some(document) => TokenFile::Codewire { entry, document },
        None => TokenFile::User,
    })
}

fn login_document(login: &AntigravityLogin) -> Document {
    let mut token = Map::new();
    token.insert(
        "access_token".to_owned(),
        Value::String(login.placeholder().to_owned()),
    );
    token.insert("token_type".to_owned(), Value::String("Bearer".to_owned()));
    token.insert(
        "refresh_token".to_owned(),
        Value::String(ANTIGRAVITY_MANAGED_REFRESH_TOKEN.to_owned()),
    );
    token.insert(
        "expiry".to_owned(),
        Value::String(MANAGED_EXPIRY_RFC3339.to_owned()),
    );
    let mut root = Map::new();
    root.insert("token".to_owned(), Value::Object(token));
    root.insert(
        "auth_method".to_owned(),
        Value::String("consumer".to_owned()),
    );
    if let Some(email) = login.account_hint() {
        root.insert("id_token_email".to_owned(), Value::String(email.to_owned()));
    }
    Document(Value::Object(root))
}

fn same_login(existing: &Document, login: &AntigravityLogin) -> bool {
    let Some(root) = existing.object() else {
        return false;
    };
    let Some(token) = existing.antigravity_token() else {
        return false;
    };
    let expected_root_len = if login.account_hint().is_some() { 3 } else { 2 };
    root.len() == expected_root_len
        && root.get("auth_method").and_then(Value::as_str) == Some("consumer")
        && root.get("id_token_email").and_then(Value::as_str) == login.account_hint()
        && token.len() == 4
        && token.get("access_token").and_then(Value::as_str) == Some(login.placeholder())
        && token.get("token_type").and_then(Value::as_str) == Some("Bearer")
        && token.get("refresh_token").and_then(Value::as_str)
            == Some(ANTIGRAVITY_MANAGED_REFRESH_TOKEN)
        && token.get("expiry").and_then(Value::as_str) == Some(MANAGED_EXPIRY_RFC3339)
}

fn install_new(config: &PrivateDirectory, contents: &[u8]) -> io::Result<bool> {
    config.install_new(
        &temporary_name("new"),
        ANTIGRAVITY_TOKEN_FILE_NAME,
        contents,
        TOKEN_FILE_MODE,
    )
}

fn replace(config: &PrivateDirectory, inspected: &OwnedEntry, contents: &[u8]) -> io::Result<bool> {
    config.replace_unchanged(
        &temporary_name("new"),
        ANTIGRAVITY_TOKEN_FILE_NAME,
        inspected,
        MAX_TOKEN_BYTES,
        contents,
        TOKEN_FILE_MODE,
    )
}

fn remove(config: &PrivateDirectory) -> io::Result<Removal> {
    match classify(config, ANTIGRAVITY_TOKEN_FILE_NAME)? {
        TokenFile::Absent => return Ok(Removal::Absent),
        TokenFile::User => return Ok(Removal::Kept),
        TokenFile::Codewire { .. } => {}
    }
    let aside = temporary_name("aside");
    match config.rename(ANTIGRAVITY_TOKEN_FILE_NAME, &aside) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Removal::Absent),
        Err(error) => return Err(error),
    }
    match classify(config, &aside)? {
        TokenFile::Absent => Ok(Removal::Absent),
        TokenFile::Codewire { .. } => {
            config.unlink(&aside)?;
            config.sync()?;
            Ok(Removal::Removed)
        }
        TokenFile::User => {
            if !config.rename_noreplace(&aside, ANTIGRAVITY_TOKEN_FILE_NAME)? {
                tracing::warn!(
                    "a new Antigravity token file appeared while Codewire checked the previous \
                     one; the previous file was kept beside it"
                );
            }
            config.sync()?;
            Ok(Removal::Kept)
        }
    }
}

fn temporary_name(purpose: &str) -> String {
    format!(
        ".{ANTIGRAVITY_TOKEN_FILE_NAME}.codewire.{}.{purpose}",
        uuid::Uuid::new_v4().simple()
    )
}

/// The Antigravity login writer for `config`, or `None` when Antigravity is
/// not selected or front-door interception is inactive.
pub(crate) fn login_writer(
    config: &crate::Config,
    owner: Option<FileOwner>,
) -> Option<AntigravityLoginWriter> {
    let bridge = config.credential_bridge.as_ref()?;
    let local = bridge.transport == crate::CredentialBridgeTransport::Local;
    if local != owner.is_some() {
        return None;
    }
    if config.interception.is_none()
        || !config
            .managed_credential_clients
            .contains(codewire_access::ManagedCredentialClient::Antigravity)
    {
        return None;
    }
    let mut writer = AntigravityLoginWriter::new(
        &config.home_root,
        ANTIGRAVITY_LOGIN_STATE_DIRECTORY,
        bridge.environment_generation,
        unix_now(),
    )
    .intercepting();
    if let Some(owner) = owner {
        writer = writer.for_owner(owner);
    }
    if let Err(error) = writer.remove_leftovers() {
        tracing::warn!(
            error_kind = ?error.kind(),
            "Antigravity login leftovers could not be removed"
        );
    }
    Some(writer)
}

pub(crate) trait AntigravityLoginSource: Send + Sync + 'static {
    fn antigravity_login(
        &self,
    ) -> impl Future<Output = Result<OpenedAntigravityLogin, LoginFailure>> + Send;
}

impl AntigravityLoginSource for codewire_credential_bridge::CredentialBridge {
    fn antigravity_login(
        &self,
    ) -> impl Future<Output = Result<OpenedAntigravityLogin, LoginFailure>> + Send {
        codewire_credential_bridge::CredentialBridge::antigravity_login(self)
    }
}

impl LoginOutcome for AntigravityLoginSync {
    const FAILED: Self = Self::Unavailable;

    fn retries_soon(self) -> bool {
        matches!(self, Self::Unavailable | Self::Lapsed)
    }
}

impl LoginWriter for AntigravityLoginWriter {
    type Delivery = AntigravityLoginDelivery;
    type Outcome = AntigravityLoginSync;

    fn apply(
        &mut self,
        delivery: AntigravityLoginDelivery,
        now_unix: u64,
    ) -> io::Result<AntigravityLoginSync> {
        AntigravityLoginWriter::apply(self, delivery, now_unix)
    }

    fn checked(outcome: AntigravityLoginSync) {
        tracing::info!(antigravity_login = ?outcome, "Antigravity login checked");
    }

    fn failed(error: &io::Error) {
        tracing::warn!(error_kind = ?error.kind(), "Antigravity login check failed");
    }

    fn stopped_unexpectedly() {
        tracing::warn!("Antigravity login check stopped unexpectedly");
    }
}

pub(crate) async fn run_antigravity_login_writer(
    writer: AntigravityLoginWriter,
    source: impl AntigravityLoginSource,
    check_period: Duration,
    shutdown: watch::Receiver<bool>,
    settle: Option<crate::login_readiness::Settle>,
) {
    let ask = || {
        let login = source.antigravity_login();
        async move { AntigravityLoginDelivery::from(login.await) }
    };
    run_login_writer(writer, ask, check_period, shutdown, settle).await;
}

#[cfg(test)]
#[path = "antigravity_home/tests.rs"]
mod tests;
