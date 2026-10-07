//! Managed agent conversations on trusted hosts and native Linux guests.
//!
//! `cw run --agent` launches `cw _agent-driver` as an ordinary durable session.
//! The driver owns the installed native agent's stdio protocol. The CLI reaches
//! it only through owner-private message records plus acknowledged session input
//! that names a record; the retained transcript is never parsed as protocol.
//! Records hold no credentials, and the native agent keeps its ordinary login
//! and HOME. Ambiguous delivery is recorded as unknown and never replayed.
use super::*;
use serde_json::{Value, json};
use std::collections::{HashMap, HashSet, VecDeque};
use std::io::{BufRead as _, Read as _};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::Path;
use tokio::io::{AsyncBufRead, AsyncBufReadExt as _, AsyncWriteExt as _};

#[cfg(target_os = "linux")]
mod guest_peer;
#[cfg(target_os = "linux")]
pub(super) mod host_control;
#[cfg(target_os = "linux")]
mod native;
#[cfg(target_os = "linux")]
mod native_host;
#[cfg(target_os = "linux")]
mod platform_control;
pub(crate) mod platform_host;
#[cfg(target_os = "linux")]
pub(crate) use guest_peer::{AgentPeerArgs, run_agent_peer};
#[cfg(target_os = "linux")]
pub(crate) use native::{AgentControlArgs, run_agent_control};
#[cfg(target_os = "linux")]
pub(crate) use platform_control::run_platform_agent_control;
#[cfg(target_os = "linux")]
pub(crate) use platform_control::{run_platform_agent_driver, run_platform_agent_peer};

#[cfg(target_os = "linux")]
const GUEST_AGENT_PROTOCOL_VERSION: u32 = 1;

/// The guest owns only its local journals and provider subprocesses. It never
/// receives a host registry, supervisor connection or daemon credential.
#[derive(Clone)]
enum DriverEnvironment {
    Host(HostEnvironment),
    Guest { id: String, root: PathBuf },
}

trait AgentStore {
    fn root(&self) -> PathBuf;
    fn id(&self) -> &str;
}

impl AgentStore for HostEnvironment {
    fn root(&self) -> PathBuf {
        HostEnvironment::root(self)
    }

    fn id(&self) -> &str {
        &self.id
    }
}

impl AgentStore for DriverEnvironment {
    fn root(&self) -> PathBuf {
        match self {
            Self::Host(environment) => environment.root(),
            Self::Guest { root, .. } => root.clone(),
        }
    }

    fn id(&self) -> &str {
        match self {
            Self::Host(environment) => &environment.id,
            Self::Guest { id, .. } => id,
        }
    }
}

impl DriverEnvironment {
    fn host(&self) -> Option<&HostEnvironment> {
        match self {
            Self::Host(environment) => Some(environment),
            Self::Guest { .. } => None,
        }
    }
}

const DRIVER_COMMAND: &str = "_agent-driver";
const HOST_DATA_DIR_ENV: &str = "CW_HOST_DATA_DIR";
const MAX_TEXT_BYTES: usize = 64 * 1024;
const MAX_RESULT_BYTES: usize = 1024 * 1024;
const MAX_RECORD_BYTES: u64 = 4 * 1024 * 1024;
const MAX_NATIVE_LINE_BYTES: usize = 16 * 1024 * 1024;
const MAX_CONTROL_LINE_BYTES: usize = 4 * 1024;
const MAX_STDERR_LINE_BYTES: usize = 4 * 1024;
const MAX_STDERR_TOTAL_BYTES: usize = 1024 * 1024;
const MAX_MESSAGES_SCANNED: usize = 10_000;
const MAX_DRIVERS_SCANNED: usize = 10_000;
const MAX_TOKEN_BYTES: usize = 128;
const INBOX_LIMIT: usize = 100;
const ACCEPT_TIMEOUT: Duration = Duration::from_secs(30);
const BINDING_TIMEOUT: Duration = Duration::from_secs(30);
const RUN_WAIT_TIMEOUT: Duration = Duration::from_secs(30 * 60);
const NATIVE_RPC_TIMEOUT: Duration = Duration::from_secs(120);
const NATIVE_WRITE_TIMEOUT: Duration = Duration::from_secs(5);
const CONTROL_PROBE_TIMEOUT: Duration = Duration::from_secs(20);
const SESSION_CHECK_INTERVAL: Duration = Duration::from_secs(5);
const ADOPT_SCAN_INTERVAL: Duration = Duration::from_secs(10);
const POLL_INTERVAL: Duration = Duration::from_millis(200);
const LOCK_TIMEOUT: Duration = Duration::from_secs(5);
const STOP_GRACE: Duration = Duration::from_secs(5);
const CODEX_DEFAULT_MODEL: &str = "gpt-6.1-sol";
const CODEX_DEFAULT_EFFORT: &str = "max";
const CLAUDE_DEFAULT_MODEL: &str = "claude-opus-5-5";
const CODEX_POLICY: &str = "trusted host execution: Codex app-server danger-full-access and approvalPolicy never; native approval requests are declined";
const CLAUDE_POLICY: &str = "installed Claude CLI with the user's ordinary settings, MCP configuration and permission rules; print mode denies tools those rules do not allow";
const NOT_QUALIFIED: &str = "managed agent conversations are qualified only on trusted host environments (`cw env create --local --type host`); sandbox and platform placements are not qualified yet";

// ---------------------------------------------------------------------------
// Durable records
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
enum AgentKind {
    Codex,
    Claude,
}

impl AgentKind {
    fn name(self) -> &'static str {
        match self {
            Self::Codex => "codex",
            Self::Claude => "claude",
        }
    }

    fn default_model(self) -> &'static str {
        match self {
            Self::Codex => CODEX_DEFAULT_MODEL,
            Self::Claude => CLAUDE_DEFAULT_MODEL,
        }
    }
}

fn agent_effort(agent: AgentKind, requested: Option<&str>) -> anyhow::Result<Option<String>> {
    let effort = match agent {
        AgentKind::Codex => Some(requested.unwrap_or(CODEX_DEFAULT_EFFORT)),
        AgentKind::Claude => requested,
    };
    if let Some(effort) = effort {
        validate_token("effort", effort)?;
        if agent == AgentKind::Claude
            && !matches!(effort, "low" | "medium" | "high" | "xhigh" | "max")
        {
            anyhow::bail!("Claude --effort supports low, medium, high, xhigh or max");
        }
    }
    Ok(effort.map(str::to_owned))
}

/// Launch-time configuration written by the CLI before the driver starts.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct AgentConfig {
    version: u32,
    driver_id: String,
    environment_id: String,
    agent: AgentKind,
    program: PathBuf,
    model: String,
    effort: Option<String>,
    working_dir: String,
    name: String,
    parent: Option<ParentLink>,
    initial_message_id: Option<String>,
    created_at: String,
}

impl AgentConfig {
    fn validate(&self, environment_id: &str, driver_id: &str) -> anyhow::Result<()> {
        if self.version != 1 || self.environment_id != environment_id || self.driver_id != driver_id
        {
            anyhow::bail!("managed conversation configuration does not match driver {driver_id}");
        }
        Ok(())
    }
}

/// Canonical parent identity resolved once at launch; never re-resolved by name.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct ParentLink {
    session_id: String,
    driver_id: String,
}

/// Written once by the launching CLI after the daemon returns the session ID.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct AgentBinding {
    driver_id: String,
    session_id: String,
    bound_at: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
enum DriverPhase {
    Starting,
    Idle,
    Busy,
    Stopped,
    Failed,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct AgentCapabilities {
    steer: bool,
    interrupt: bool,
    note: String,
}

/// Written only by the driver that holds `driver.lock`.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct DriverState {
    version: u32,
    driver_id: String,
    agent: AgentKind,
    phase: DriverPhase,
    native_thread_id: Option<String>,
    native_thread_established: bool,
    current_turn_id: Option<String>,
    active_message_id: Option<String>,
    queued: usize,
    capabilities: AgentCapabilities,
    policy: String,
    last_error: Option<String>,
    started_at: String,
    updated_at: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
enum MessageAction {
    Prompt,
    Message,
    Steer,
    Interrupt,
    Notification,
}

impl MessageAction {
    fn name(self) -> &'static str {
        match self {
            Self::Prompt => "prompt",
            Self::Message => "message",
            Self::Steer => "steer",
            Self::Interrupt => "interrupt",
            Self::Notification => "notification",
        }
    }

    fn starts_turn(self) -> bool {
        matches!(self, Self::Prompt | Self::Message | Self::Notification)
    }
}

/// `accepted` is persisted by the driver before queueing and `running` before
/// any provider write, so `accepted` proves the message was never issued.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
enum MessageState {
    Requested,
    PipeWritten,
    Undelivered,
    Accepted,
    Running,
    Completed,
    Error,
    Interrupted,
    Unknown,
}

impl MessageState {
    fn name(self) -> &'static str {
        match self {
            Self::Requested => "requested",
            Self::PipeWritten => "pipe_written",
            Self::Undelivered => "undelivered",
            Self::Accepted => "accepted",
            Self::Running => "running",
            Self::Completed => "completed",
            Self::Error => "error",
            Self::Interrupted => "interrupted",
            Self::Unknown => "unknown",
        }
    }

    fn rank(self) -> u8 {
        match self {
            Self::Requested => 0,
            Self::PipeWritten | Self::Undelivered => 1,
            Self::Accepted => 2,
            Self::Running => 3,
            Self::Completed | Self::Error | Self::Interrupted | Self::Unknown => 4,
        }
    }

    fn is_terminal(self) -> bool {
        self.rank() == 4
    }
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct MessageSource {
    session_id: String,
    driver_id: String,
    message_id: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
enum NotificationState {
    Pending,
    Undelivered,
    PipeWritten,
    Unknown,
    Error,
}

/// Sender-side delivery record. The receiver's own record carries acceptance.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct ParentNotification {
    message_id: String,
    parent_session_id: String,
    parent_driver_id: String,
    state: NotificationState,
    detail: Option<String>,
    updated_at: String,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct MessageRecord {
    version: u32,
    id: String,
    driver_id: String,
    target_session_id: String,
    action: MessageAction,
    text: String,
    reply_to: Option<String>,
    expected_turn_id: Option<String>,
    expected_active_message_id: Option<String>,
    turn_id: Option<String>,
    state: MessageState,
    created_at: String,
    updated_at: String,
    accepted_at: Option<String>,
    started_at: Option<String>,
    finished_at: Option<String>,
    native_acknowledged: bool,
    /// Target-owned birth proof for member messages; ordinary records keep
    /// their established wire bytes and do not acquire a guessed generation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    member_launch_generation: Option<u64>,
    /// Platform original Pod/session generation; never inferred from Host/Mesh.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    platform_launch_generation: Option<u64>,
    result: Option<String>,
    result_truncated: bool,
    error: Option<String>,
    usage: Option<Value>,
    source: Option<MessageSource>,
    notification: Option<ParentNotification>,
}

fn member_message_generation_matches(current: Option<u64>, record: &MessageRecord) -> bool {
    match current {
        Some(generation) => generation > 0 && record.member_launch_generation == Some(generation),
        None => record.member_launch_generation.is_none(),
    }
}
fn managed_message_generation_matches(
    current: (Option<u64>, Option<u64>),
    record: &MessageRecord,
) -> bool {
    member_message_generation_matches(current.0, record)
        && match current.1 {
            Some(generation) => {
                generation > 0 && record.platform_launch_generation == Some(generation)
            }
            None => record.platform_launch_generation.is_none(),
        }
}

impl MessageRecord {
    fn new(driver_id: &str, target_session_id: &str, action: MessageAction, text: String) -> Self {
        let created = now();
        Self {
            version: 1,
            id: uuid::Uuid::new_v4().to_string(),
            driver_id: driver_id.into(),
            target_session_id: target_session_id.into(),
            action,
            text,
            reply_to: None,
            expected_turn_id: None,
            expected_active_message_id: None,
            turn_id: None,
            state: MessageState::Requested,
            created_at: created.clone(),
            updated_at: created,
            accepted_at: None,
            started_at: None,
            finished_at: None,
            native_acknowledged: false,
            member_launch_generation: None,
            platform_launch_generation: None,
            result: None,
            result_truncated: false,
            error: None,
            usage: None,
            source: None,
            notification: None,
        }
    }

    /// Monotonic transition; terminal states never change.
    fn transition(&mut self, next: MessageState) -> bool {
        if self.state.is_terminal() || next.rank() <= self.state.rank() {
            return false;
        }
        let at = now();
        match next {
            MessageState::Accepted => self.accepted_at = Some(at.clone()),
            MessageState::Running => self.started_at = Some(at.clone()),
            state if state.is_terminal() => self.finished_at = Some(at.clone()),
            _ => {}
        }
        self.state = next;
        self.updated_at = at;
        true
    }

    fn fail(&mut self, state: MessageState, error: impl Into<String>) -> bool {
        if self.state.is_terminal() {
            return false;
        }
        self.error = Some(error.into());
        self.transition(state)
    }

    /// The driver decides a queued message when it admits it. Only the
    /// provider decides a steer or interrupt, so those wait for its answer.
    fn decided(&self) -> bool {
        self.state.is_terminal()
            || match self.action {
                MessageAction::Steer | MessageAction::Interrupt => self.native_acknowledged,
                _ => self.state.rank() >= MessageState::Accepted.rank(),
            }
    }

    fn validate(&self, dir: &Path, id: &str) -> anyhow::Result<()> {
        if self.version != 1
            || self.id != id
            || Some(self.driver_id.as_str()) != dir_driver_id(dir)
            || self.member_launch_generation == Some(0)
            || self.platform_launch_generation == Some(0)
            || (self.member_launch_generation.is_some()
                && self.platform_launch_generation.is_some())
        {
            anyhow::bail!("message record {id} does not belong to this conversation");
        }
        Ok(())
    }
}

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct ControlLine {
    v: u32,
    op: ControlOp,
    driver_id: String,
    message_id: String,
}

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
enum ControlOp {
    Deliver,
    Shutdown,
}

fn control_line(driver_id: &str, message_id: &str) -> anyhow::Result<Vec<u8>> {
    let mut line = serde_json::to_vec(&ControlLine {
        v: 1,
        op: ControlOp::Deliver,
        driver_id: driver_id.into(),
        message_id: message_id.into(),
    })?;
    line.push(b'\n');
    Ok(line)
}

#[cfg(target_os = "linux")]
fn shutdown_control_line(driver_id: &str, operation_id: &str) -> anyhow::Result<Vec<u8>> {
    let mut line = serde_json::to_vec(&ControlLine {
        v: 1,
        op: ControlOp::Shutdown,
        driver_id: canonical_uuid(driver_id)?,
        message_id: canonical_uuid(operation_id)?,
    })?;
    line.push(b'\n');
    Ok(line)
}

// ---------------------------------------------------------------------------
// Validation and private storage
// ---------------------------------------------------------------------------

fn now() -> String {
    Utc::now().to_rfc3339_opts(SecondsFormat::Micros, true)
}

fn euid() -> u32 {
    // SAFETY: geteuid reads the current process identity.
    unsafe { libc::geteuid() }
}

fn log(message: impl std::fmt::Display) {
    eprintln!("cw agent driver: {message}");
}

fn canonical_uuid(value: &str) -> anyhow::Result<String> {
    let parsed =
        uuid::Uuid::parse_str(value).with_context(|| format!("{value:?} is not a valid ID"))?;
    let canonical = parsed.hyphenated().to_string();
    if canonical != value {
        anyhow::bail!("{value:?} is not a canonical lowercase UUID");
    }
    Ok(canonical)
}

fn validate_text(text: &str) -> anyhow::Result<()> {
    if text.trim().is_empty() {
        anyhow::bail!("message text is empty");
    }
    if text.len() > MAX_TEXT_BYTES {
        anyhow::bail!("message text exceeds {MAX_TEXT_BYTES} bytes");
    }
    if text.contains('\0') {
        anyhow::bail!("message text contains a NUL byte");
    }
    Ok(())
}

fn validate_token(kind: &str, value: &str) -> anyhow::Result<()> {
    if value.is_empty()
        || value.len() > MAX_TOKEN_BYTES
        || !value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._:/-".contains(&b))
    {
        anyhow::bail!(
            "{kind} must be 1-{MAX_TOKEN_BYTES} letters, numbers, '.', '_', ':', '/' or '-'"
        );
    }
    Ok(())
}

fn truncate_utf8(value: &str, max: usize) -> (String, bool) {
    if value.len() <= max {
        return (value.to_owned(), false);
    }
    let mut end = max;
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    (value[..end].to_owned(), true)
}

fn existing_private_dir(path: &Path) -> anyhow::Result<()> {
    let meta = fs::symlink_metadata(path)
        .with_context(|| format!("managed conversation state {} is missing", path.display()))?;
    if !meta.is_dir() || meta.uid() != euid() || meta.permissions().mode() & 0o077 != 0 {
        anyhow::bail!(
            "managed conversation state must be an owner-private directory, not a symlink: {}",
            path.display()
        );
    }
    Ok(())
}

fn read_record<T: serde::de::DeserializeOwned>(path: &Path) -> anyhow::Result<T> {
    let file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(path)
        .with_context(|| format!("open {}", path.display()))?;
    let meta = file.metadata()?;
    if !meta.is_file() || meta.uid() != euid() || meta.permissions().mode() & 0o077 != 0 {
        anyhow::bail!(
            "managed conversation record must be an owner-private file: {}",
            path.display()
        );
    }
    if meta.len() > MAX_RECORD_BYTES {
        anyhow::bail!(
            "managed conversation record exceeds {MAX_RECORD_BYTES} bytes: {}",
            path.display()
        );
    }
    let mut data = Vec::new();
    file.take(MAX_RECORD_BYTES + 1).read_to_end(&mut data)?;
    if data.len() as u64 > MAX_RECORD_BYTES {
        anyhow::bail!(
            "managed conversation record grew beyond {MAX_RECORD_BYTES} bytes: {}",
            path.display()
        );
    }
    serde_json::from_slice(&data).with_context(|| format!("parse {}", path.display()))
}

fn read_optional<T: serde::de::DeserializeOwned>(path: &Path) -> anyhow::Result<Option<T>> {
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
        Ok(_) => read_record(path).map(Some),
    }
}

/// Short advisory lock for read-modify-write of message records. Never nest.
struct StateLock(fs::File);

impl StateLock {
    fn try_acquire(path: &Path) -> anyhow::Result<Option<Self>> {
        let file = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
            .open(path)
            .with_context(|| format!("open lock {}", path.display()))?;
        let held = file.metadata()?;
        let named = fs::symlink_metadata(path)?;
        if !held.is_file()
            || held.uid() != euid()
            || held.mode() & 0o7777 != 0o600
            || held.nlink() != 1
            || held.dev() != named.dev()
            || held.ino() != named.ino()
            || held.mode() != named.mode()
            || held.uid() != named.uid()
            || held.nlink() != named.nlink()
        {
            anyhow::bail!("managed conversation lock is unsafe");
        }
        // SAFETY: the descriptor remains owned by the returned guard.
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 {
            return Ok(Some(Self(file)));
        }
        let error = std::io::Error::last_os_error();
        if error.kind() == std::io::ErrorKind::WouldBlock {
            Ok(None)
        } else {
            Err(error.into())
        }
    }

    fn acquire(path: &Path) -> anyhow::Result<Self> {
        let deadline = Instant::now() + LOCK_TIMEOUT;
        loop {
            if let Some(lock) = Self::try_acquire(path)? {
                return Ok(lock);
            }
            if Instant::now() >= deadline {
                anyhow::bail!(
                    "managed conversation state is locked by another process: {}",
                    path.display()
                );
            }
            std::thread::sleep(Duration::from_millis(5));
        }
    }
}

impl Drop for StateLock {
    fn drop(&mut self) {
        // SAFETY: unlock the descriptor owned by this guard before close.
        unsafe {
            libc::flock(self.0.as_raw_fd(), libc::LOCK_UN);
        }
    }
}

fn agents_root(environment: &impl AgentStore) -> PathBuf {
    environment.root().join("agents")
}

fn dir_driver_id(dir: &Path) -> Option<&str> {
    dir.file_name().and_then(|name| name.to_str())
}

fn driver_dir(environment: &impl AgentStore, driver_id: &str) -> anyhow::Result<PathBuf> {
    let driver_id = canonical_uuid(driver_id)?;
    existing_private_dir(&environment.root())?;
    let root = agents_root(environment);
    existing_private_dir(&root)?;
    let dir = root.join(driver_id);
    existing_private_dir(&dir)?;
    existing_private_dir(&dir.join("messages"))?;
    Ok(dir)
}

fn message_path(dir: &Path, id: &str) -> PathBuf {
    dir.join("messages").join(format!("{id}.json"))
}

fn load_message(dir: &Path, id: &str) -> anyhow::Result<MessageRecord> {
    let id = canonical_uuid(id)?;
    let record: MessageRecord = read_record(&message_path(dir, &id))?;
    record.validate(dir, &id)?;
    Ok(record)
}

/// Creates a record once. Returns false when the ID already exists.
fn create_message(dir: &Path, record: &MessageRecord) -> anyhow::Result<bool> {
    let _lock = StateLock::acquire(&dir.join("messages.lock"))?;
    let path = message_path(dir, &record.id);
    match fs::symlink_metadata(&path) {
        Ok(_) => return Ok(false),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    write_private_json(&path, record)?;
    Ok(true)
}

fn update_message(
    dir: &Path,
    id: &str,
    apply: impl FnOnce(&mut MessageRecord),
) -> anyhow::Result<MessageRecord> {
    let _lock = StateLock::acquire(&dir.join("messages.lock"))?;
    let mut record = load_message(dir, id)?;
    apply(&mut record);
    // Keep records readable even for a native peer's oversized error/usage.
    record.error = record.error.map(|text| truncate_utf8(&text, 128 * 1024).0);
    if record.usage.as_ref().is_some_and(|usage| {
        serde_json::to_vec(usage).map_or(true, |bytes| bytes.len() > 64 * 1024)
    }) {
        record.usage = Some(json!({"truncated": true}));
    }
    if serde_json::to_vec(&record)?.len() as u64 > MAX_RECORD_BYTES
        && let Some(result) = record.result.as_mut()
    {
        let (text, truncated) = truncate_utf8(result, 256 * 1024);
        *result = text;
        record.result_truncated |= truncated;
    }
    anyhow::ensure!(
        serde_json::to_vec(&record)?.len() as u64 <= MAX_RECORD_BYTES,
        "managed message exceeds storage limit"
    );
    write_private_json(&message_path(dir, &record.id), &record)?;
    Ok(record)
}

fn message_ids(dir: &Path) -> anyhow::Result<Vec<String>> {
    let mut ids = Vec::new();
    for (count, entry) in fs::read_dir(dir.join("messages"))?.enumerate() {
        if count >= MAX_MESSAGES_SCANNED {
            anyhow::bail!(
                "managed conversation has more than {MAX_MESSAGES_SCANNED} message records"
            );
        }
        let entry = entry?;
        let name = entry.file_name();
        let Some(id) = name.to_str().and_then(|name| name.strip_suffix(".json")) else {
            continue;
        };
        if let Ok(id) = canonical_uuid(id) {
            ids.push(id);
        }
    }
    Ok(ids)
}

fn list_messages(dir: &Path) -> anyhow::Result<Vec<MessageRecord>> {
    let mut records = message_ids(dir)?
        .iter()
        .map(|id| load_message(dir, id))
        .collect::<anyhow::Result<Vec<_>>>()?;
    records.sort_by(|a, b| {
        a.created_at
            .cmp(&b.created_at)
            .then_with(|| a.id.cmp(&b.id))
    });
    Ok(records)
}

/// Recovery keeps only bounded identity/timestamp pairs, not every retained
/// provider result. Full records are read one at a time in the same ordering.
fn ordered_message_ids(dir: &Path) -> anyhow::Result<Vec<String>> {
    let mut order = Vec::new();
    for id in message_ids(dir)? {
        let record = load_message(dir, &id)?;
        anyhow::ensure!(
            record.created_at.len() <= 64,
            "managed record timestamp exceeds bound"
        );
        order.push((record.created_at, id));
    }
    order.sort();
    Ok(order.into_iter().map(|(_, id)| id).collect())
}

/// One deterministic ID per worker message, so a parent is notified once.
fn notification_id(source_message_id: &str) -> String {
    use sha2::Digest as _;
    let digest = sha2::Sha256::digest(
        format!("codewire-agent-notification:v1:{source_message_id}").as_bytes(),
    );
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    uuid::Builder::from_random_bytes(bytes)
        .into_uuid()
        .to_string()
}

/// Errors raised before any byte could reach the receiver's pipe.
fn send_error_is_definitive(error: &codewire_daemon::client::SessionClientError) -> bool {
    use codewire_daemon::client::SessionClientError as E;
    match error {
        E::InvalidEndpoint
        | E::InvalidCredential
        | E::Connect
        | E::NotReady { .. }
        | E::MissingCapability { .. } => true,
        E::Status(status) => matches!(
            status.code(),
            tonic::Code::InvalidArgument
                | tonic::Code::NotFound
                | tonic::Code::PermissionDenied
                | tonic::Code::Unauthenticated
                | tonic::Code::Unimplemented
        ),
        E::RequestClosed | E::MissingSessionRecord => false,
        #[allow(unreachable_patterns)]
        _ => false,
    }
}

fn apply_delivery_failure(record: &mut MessageRecord, definitive: bool, error: &str) {
    if record.state.rank() >= MessageState::Accepted.rank() {
        return;
    }
    if definitive {
        record.fail(
            MessageState::Error,
            format!("not delivered to the driver: {error}"),
        );
    } else {
        record.fail(
            MessageState::Unknown,
            format!("driver pipe write outcome unknown ({error}); not replayed"),
        );
    }
}

// ---------------------------------------------------------------------------
// CLI surface
// ---------------------------------------------------------------------------

/// Managed drivers own their input; raw send and interactive attach must refuse.
pub(crate) fn is_managed_session(view: &EnvironmentSessionView) -> bool {
    view.command.iter().any(|arg| {
        arg == DRIVER_COMMAND || (cfg!(target_os = "linux") && arg == "__platform-agent-driver")
    })
}

#[cfg(target_os = "linux")]
pub(super) async fn stop_native_managed(
    target: &EnvironmentSessionTarget,
    session: &EnvironmentSessionView,
) -> anyhow::Result<EnvironmentSessionView> {
    native_host::stop(target.clone(), session).await
}

#[cfg(target_os = "linux")]
pub(super) async fn restart_native_managed(
    target: &EnvironmentSessionTarget,
    session: &EnvironmentSessionView,
) -> anyhow::Result<EnvironmentSessionView> {
    native_host::restart(target.clone(), session).await
}

fn driver_identity(command: &[String]) -> Option<(String, String)> {
    #[cfg(target_os = "linux")]
    if command
        .get(1)
        .is_some_and(|arg| arg == "__platform-agent-driver")
    {
        if command.len() != 6
            || command[0] != "/codewire/bin/cw"
            || command[2] != "--environment"
            || command[4] != "--driver-id"
        {
            return None;
        }
        return Some((
            canonical_uuid(&command[3]).ok()?,
            canonical_uuid(&command[5]).ok()?,
        ));
    }
    let position = command.iter().position(|arg| arg == DRIVER_COMMAND)?;
    let rest = &command[position + 1..];
    let value = |flag: &str| {
        rest.windows(2)
            .find(|pair| pair[0] == flag)
            .map(|pair| pair[1].clone())
    };
    let environment = value("--environment")?;
    let driver = canonical_uuid(&value("--driver-id")?).ok()?;
    Some((environment, driver))
}

fn session_running(view: &EnvironmentSessionView) -> bool {
    view.state.eq_ignore_ascii_case("running")
}

fn session_finished(view: &EnvironmentSessionView) -> bool {
    ["exited", "failed", "stopped", "interrupted"]
        .iter()
        .any(|state| view.state.eq_ignore_ascii_case(state))
}

fn session_label(view: &EnvironmentSessionView) -> String {
    if view.name.is_empty() {
        view.session_id.clone()
    } else {
        format!("{} ({})", view.name, view.session_id)
    }
}

fn host_placement(target: &EnvironmentSessionTarget) -> anyhow::Result<&HostEnvironment> {
    match target {
        EnvironmentSessionTarget::Host { environment, .. } => Ok(environment),
        _ => anyhow::bail!("{NOT_QUALIFIED}"),
    }
}

fn host_target(environment: &HostEnvironment) -> EnvironmentSessionTarget {
    EnvironmentSessionTarget::Host {
        target: environment.current_target(),
        environment: environment.clone(),
    }
}

struct ManagedConversation {
    environment: HostEnvironment,
    session: EnvironmentSessionView,
    dir: PathBuf,
    config: AgentConfig,
}

fn managed_conversation(
    environment: &HostEnvironment,
    session: EnvironmentSessionView,
) -> anyhow::Result<ManagedConversation> {
    if !is_managed_session(&session) {
        anyhow::bail!(
            "session {} is not a managed agent conversation; use `cw send` for raw input",
            session_label(&session)
        );
    }
    let (environment_id, driver_id) = driver_identity(&session.command)
        .context("managed session command has no valid driver identity")?;
    if environment_id != environment.id {
        anyhow::bail!(
            "managed session {} belongs to a different host environment",
            session.session_id
        );
    }
    let dir = driver_dir(environment, &driver_id)?;
    let config: AgentConfig = read_record(&dir.join("config.json"))?;
    config.validate(&environment.id, &driver_id)?;
    let binding: AgentBinding = read_optional(&dir.join("binding.json"))?
        .context("managed conversation has no session binding; its launch did not complete")?;
    if binding.driver_id != driver_id || binding.session_id != session.session_id {
        anyhow::bail!(
            "managed conversation binding does not match session {}",
            session.session_id
        );
    }
    Ok(ManagedConversation {
        environment: environment.clone(),
        session,
        dir,
        config,
    })
}

async fn resolve_managed(
    globals: &Globals,
    environment: Option<&str>,
    session: &str,
) -> anyhow::Result<ManagedConversation> {
    let target = resolve_environment_session_target(globals, environment).await?;
    let host = host_placement(&target)?.clone();
    let view = match select_environment_session(&target, Some(session)).await? {
        SessionSelection::Select(view) => view,
        SessionSelection::Create => anyhow::bail!("session {session:?} not found"),
    };
    managed_conversation(&host, *view)
}

fn ensure_accepting(managed: &ManagedConversation) -> anyhow::Result<()> {
    if !session_running(&managed.session) {
        anyhow::bail!(
            "managed conversation {} is {}; it cannot accept messages",
            session_label(&managed.session),
            managed.session.state
        );
    }
    Ok(())
}

fn find_program(name: &str) -> anyhow::Result<PathBuf> {
    let path = env::var_os("PATH").context("PATH is not set")?;
    for dir in env::split_paths(&path) {
        if !dir.is_absolute() {
            continue;
        }
        let candidate = dir.join(name);
        if let Ok(meta) = fs::metadata(&candidate)
            && meta.is_file()
            && meta.permissions().mode() & 0o111 != 0
        {
            return Ok(candidate);
        }
    }
    anyhow::bail!(
        "the installed {name} CLI was not found on PATH; install it and sign in with its ordinary login first"
    )
}

async fn resolve_parent_link(
    target: &EnvironmentSessionTarget,
    environment: &HostEnvironment,
    requested: &str,
) -> anyhow::Result<ParentLink> {
    let session_id = resolve_parent_session(target, Some(requested)).await?;
    if session_id.is_empty() {
        anyhow::bail!("parent session {requested:?} not found");
    }
    let view = target.get(&session_id).await?;
    if view.session_id != session_id {
        anyhow::bail!("parent session identity changed during resolution");
    }
    let parent = managed_conversation(environment, view).map_err(|error| {
        anyhow::anyhow!(
            "parent {requested:?} has no semantic receiver for worker results: {error:#}. Launch the parent with `cw run --agent ...` or omit --parent"
        )
    })?;
    if !session_running(&parent.session) {
        anyhow::bail!(
            "parent conversation {} is {}; start it before launching workers",
            session_label(&parent.session),
            parent.session.state
        );
    }
    Ok(ParentLink {
        session_id: parent.session.session_id,
        driver_id: parent.config.driver_id,
    })
}

pub(super) async fn handle_agent_run_command(
    _globals: &Globals,
    target: EnvironmentSessionTarget,
    args: EnvironmentRunArgs,
) -> anyhow::Result<()> {
    if matches!(target, EnvironmentSessionTarget::Platform { .. }) {
        return platform_host::run(target, args).await;
    }
    #[cfg(target_os = "linux")]
    if matches!(target, EnvironmentSessionTarget::NativeLocal { .. }) {
        return native_host::run(target, args).await;
    }
    #[cfg(target_os = "macos")]
    if matches!(target, EnvironmentSessionTarget::NativeLocal { .. }) {
        anyhow::bail!("managed agents are not available in macOS local environments yet");
    }
    let environment = host_placement(&target)?.clone();
    let agent = match args.agent.as_deref() {
        Some("codex") => AgentKind::Codex,
        Some("claude") => AgentKind::Claude,
        Some("kimi") => anyhow::bail!(
            "Kimi managed conversations are not qualified yet: its ACP adapter has not passed Codewire qualification. Use --agent codex or --agent claude"
        ),
        Some(other) => anyhow::bail!("unsupported managed agent {other:?}"),
        None => anyhow::bail!("--agent is required for a managed conversation"),
    };
    if args.tty {
        anyhow::bail!(
            "managed conversations use a structured protocol without a terminal; omit --tty"
        );
    }
    if !args.command.is_empty() {
        anyhow::bail!("managed conversations launch the selected agent; omit COMMAND");
    }
    let model = args
        .model
        .clone()
        .unwrap_or_else(|| agent.default_model().into());
    validate_token("model", &model)?;
    let effort = agent_effort(agent, args.effort.as_deref())?;
    if let Some(prompt) = &args.prompt {
        validate_text(prompt)?;
    }
    let program = find_program(agent.name())?;
    let name = args.name.clone().unwrap_or_default();
    let working_dir = args
        .workdir
        .clone()
        .unwrap_or_else(|| target.default_working_dir());
    let launch_env = parse_env_overrides(&args.env)?;
    target.ensure_ready_for_run()?;
    let parent = match args.parent.as_deref().and_then(trimmed_str) {
        Some(requested) => Some(resolve_parent_link(&target, &environment, requested).await?),
        None => None,
    };

    let driver_id = uuid::Uuid::new_v4().to_string();
    let root = agents_root(&environment);
    private_directory(&root)?;
    let dir = root.join(&driver_id);
    private_directory(&dir)?;
    private_directory(&dir.join("messages"))?;
    let initial_message_id = args
        .prompt
        .as_ref()
        .map(|_| uuid::Uuid::new_v4().to_string());
    let config = AgentConfig {
        version: 1,
        driver_id: driver_id.clone(),
        environment_id: environment.id.clone(),
        agent,
        program,
        model: model.clone(),
        effort: effort.clone(),
        working_dir: working_dir.clone(),
        name: name.clone(),
        parent: parent.clone(),
        initial_message_id: initial_message_id.clone(),
        created_at: now(),
    };
    write_private_json(&dir.join("config.json"), &config)?;
    let executable = env::current_exe()
        .context("locate the installed cw executable")?
        .into_os_string()
        .into_string()
        .map_err(|_| anyhow::anyhow!("the cw executable path is not UTF-8"))?;
    let command = vec![
        executable,
        DRIVER_COMMAND.into(),
        "--environment".into(),
        environment.id.clone(),
        "--driver-id".into(),
        driver_id.clone(),
        "--registry-root".into(),
        environment
            .root()
            .parent()
            .context("host registry parent")?
            .to_str()
            .context("host registry path is not UTF-8")?
            .into(),
    ];
    let parent_session_id = parent
        .as_ref()
        .map(|p| p.session_id.clone())
        .unwrap_or_default();
    let session = target
        .launch(
            command,
            working_dir,
            launch_env,
            false,
            name,
            parent_session_id,
        )
        .await
        .with_context(|| format!("launch managed {} driver {driver_id}", agent.name()))?;
    if let (Some(id), Some(prompt)) = (&initial_message_id, &args.prompt) {
        let mut record = MessageRecord::new(
            &driver_id,
            &session.session_id,
            MessageAction::Prompt,
            prompt.clone(),
        );
        record.id = id.clone();
        if !create_message(&dir, &record)? {
            anyhow::bail!("initial message {id} already exists");
        }
    }
    // The driver waits for this binding before it accepts or delivers anything.
    write_private_json(
        &dir.join("binding.json"),
        &AgentBinding {
            driver_id: driver_id.clone(),
            session_id: session.session_id.clone(),
            bound_at: now(),
        },
    )?;
    if matches!(args.output, OutputFormat::Text) {
        eprintln!(
            "Launched managed {} conversation {} (driver {driver_id})",
            agent.name(),
            session_label(&session)
        );
    }

    let mut message = None;
    let mut failure = None;
    if let Some(id) = &initial_message_id {
        let accepted = await_acceptance(&dir, id).await?;
        if args.detach || accepted.state.is_terminal() {
            message = Some(accepted);
        } else {
            let (record, end) = wait_for_message(&environment, &dir, id, RUN_WAIT_TIMEOUT).await?;
            failure = wait_failure(&record, &end);
            message = Some(record);
        }
        if failure.is_none()
            && let Some(record) = &message
        {
            failure = message_failure(record);
        }
    }
    match args.output {
        OutputFormat::Json => println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "session": session,
                "driver_id": driver_id,
                "agent": agent.name(),
                "model": model,
                "effort": effort,
                "parent_session_id": parent.as_ref().map(|p| p.session_id.clone()),
                "message": message,
            }))?
        ),
        OutputFormat::Text => match &message {
            Some(record) if args.detach || !record.state.is_terminal() => {
                println!("{}\t{}", record.id, record.state.name());
            }
            Some(record) => print_message_result(record, OutputFormat::Text)?,
            None => println!("{}", session.session_id),
        },
    }
    match failure {
        Some(failure) => Err(failure),
        None => Ok(()),
    }
}

pub(crate) async fn handle_agent_message_command(
    globals: &Globals,
    args: AgentMessageArgs,
    steer: bool,
) -> anyhow::Result<()> {
    #[cfg(target_os = "linux")]
    if globals.member.is_some() {
        return super::super::member_control::managed::send_message(globals, args, steer).await;
    }
    let (environment, session, text) = match args.target_and_text.as_slice() {
        [session, text] => (None, session.as_str(), text.as_str()),
        [environment, session, text] => {
            (Some(environment.as_str()), session.as_str(), text.as_str())
        }
        _ => anyhow::bail!("expected SESSION TEXT or ENV SESSION TEXT"),
    };
    validate_text(text)?;
    let reply_to = args.reply_to.as_deref().map(canonical_uuid).transpose()?;
    if !steer && args.turn_id.is_some() {
        anyhow::bail!("--turn-id applies only to `cw steer`");
    }
    if let Some(turn) = &args.turn_id {
        validate_token("turn ID", turn)?;
    }
    let target = resolve_environment_session_target(globals, environment).await?;
    if matches!(target, EnvironmentSessionTarget::Platform { .. }) {
        return platform_host::message(target, session, &args, text, steer).await;
    }
    #[cfg(target_os = "linux")]
    {
        let target = resolve_environment_session_target(globals, environment).await?;
        if matches!(target, EnvironmentSessionTarget::NativeLocal { .. }) {
            return native_host::message(
                target,
                session,
                text,
                reply_to,
                args.turn_id.clone(),
                steer,
                args.output,
            )
            .await;
        }
    }
    let managed = resolve_managed(globals, environment, session).await?;
    ensure_accepting(&managed)?;
    let mut record = MessageRecord::new(
        &managed.config.driver_id,
        &managed.session.session_id,
        if steer {
            MessageAction::Steer
        } else {
            MessageAction::Message
        },
        text.to_owned(),
    );
    record.reply_to = reply_to;
    if steer {
        let state = read_optional::<DriverState>(&managed.dir.join("state.json"))?
            .context("the managed driver has not reported its capabilities yet")?;
        if !state.capabilities.steer {
            anyhow::bail!(
                "{} conversations do not support steering: {}",
                managed.config.agent.name(),
                state.capabilities.note
            );
        }
        record.expected_turn_id = Some(match args.turn_id.clone() {
            Some(turn) => turn,
            None => state
                .current_turn_id
                .clone()
                .context("no active turn to steer; use `cw msg` to queue a message")?,
        });
    }
    let record = deliver_cli_message(&managed, record).await?;
    print_message_summary(&record, args.output)?;
    match message_failure(&record) {
        Some(failure) => Err(failure),
        None => Ok(()),
    }
}

pub(crate) async fn handle_agent_interrupt_command(
    globals: &Globals,
    args: SessionTargetArgs,
) -> anyhow::Result<()> {
    #[cfg(target_os = "linux")]
    if globals.member.is_some() {
        return super::super::member_control::managed::action(
            globals,
            args,
            codewire_daemon_proto::daemon::v1::HostManagedAction::Interrupt,
        )
        .await;
    }
    let (environment, session) = split_session_target(&args.target)?;
    let target = resolve_environment_session_target(globals, environment).await?;
    if matches!(target, EnvironmentSessionTarget::Platform { .. }) {
        return platform_host::action(
            target,
            session,
            &args,
            codewire_client::platform_agents::EnvironmentAgentAction::Interrupt,
        )
        .await;
    }
    #[cfg(target_os = "linux")]
    {
        let target = resolve_environment_session_target(globals, environment).await?;
        if matches!(target, EnvironmentSessionTarget::NativeLocal { .. }) {
            return native_host::interrupt(target, session, args.output).await;
        }
    }
    let managed = resolve_managed(globals, environment, session).await?;
    ensure_accepting(&managed)?;
    let state = read_optional::<DriverState>(&managed.dir.join("state.json"))?
        .context("the managed driver has not reported its capabilities yet")?;
    if !state.capabilities.interrupt {
        anyhow::bail!(
            "{} conversations do not support interrupt: {}",
            managed.config.agent.name(),
            state.capabilities.note
        );
    }
    let active = state
        .active_message_id
        .clone()
        .context("no active turn to interrupt")?;
    let mut record = MessageRecord::new(
        &managed.config.driver_id,
        &managed.session.session_id,
        MessageAction::Interrupt,
        String::new(),
    );
    record.expected_active_message_id = Some(active);
    record.expected_turn_id = state.current_turn_id.clone();
    let record = deliver_cli_message(&managed, record).await?;
    print_message_summary(&record, args.output)?;
    match message_failure(&record) {
        Some(failure) => Err(failure),
        None => Ok(()),
    }
}

pub(crate) async fn handle_agent_inbox_command(
    globals: &Globals,
    args: SessionTargetArgs,
) -> anyhow::Result<()> {
    #[cfg(target_os = "linux")]
    if globals.member.is_some() {
        return super::super::member_control::managed::inbox(globals, args).await;
    }
    let (environment, session) = split_session_target(&args.target)?;
    let target = resolve_environment_session_target(globals, environment).await?;
    if matches!(target, EnvironmentSessionTarget::Platform { .. }) {
        return platform_host::inbox(target, session, args.output).await;
    }
    #[cfg(target_os = "linux")]
    {
        let target = resolve_environment_session_target(globals, environment).await?;
        if matches!(target, EnvironmentSessionTarget::NativeLocal { .. }) {
            return native_host::inbox(target, session, args.output).await;
        }
    }
    let managed = resolve_managed(globals, environment, session).await?;
    let state = read_optional::<DriverState>(&managed.dir.join("state.json"))?;
    let mut messages = list_messages(&managed.dir)?;
    let total = messages.len();
    if total > INBOX_LIMIT {
        messages = messages.split_off(total - INBOX_LIMIT);
    }
    match args.output {
        OutputFormat::Json => {
            let views: Vec<Value> = messages
                .iter()
                .map(|record| message_view(&managed.environment, record))
                .collect();
            println!(
                "{}",
                serde_json::to_string_pretty(&json!({
                    "environment_id": managed.environment.id,
                    "session_id": managed.session.session_id,
                    "session_state": managed.session.state,
                    "driver_id": managed.config.driver_id,
                    "agent": managed.config.agent.name(),
                    "model": managed.config.model,
                    "effort": managed.config.effort,
                    "parent": managed.config.parent,
                    "driver": state,
                    "messages_total": total,
                    "messages": views,
                }))?
            );
        }
        OutputFormat::Text => {
            match &state {
                Some(state) => println!(
                    "{}\t{}\t{}\tsession {}\tdriver {}\tturn {}\tqueued {}\tsteer {}\tinterrupt {}",
                    session_label(&managed.session),
                    managed.config.agent.name(),
                    managed.config.model,
                    managed.session.state,
                    serde_json::to_value(state.phase)?
                        .as_str()
                        .unwrap_or("unknown"),
                    state
                        .current_turn_id
                        .as_deref()
                        .or(state.active_message_id.as_deref())
                        .unwrap_or("-"),
                    state.queued,
                    if state.capabilities.steer {
                        "yes"
                    } else {
                        "no"
                    },
                    if state.capabilities.interrupt {
                        "yes"
                    } else {
                        "no"
                    },
                ),
                None => println!(
                    "{}\t{}\t{}\tsession {}\tdriver has not reported state",
                    session_label(&managed.session),
                    managed.config.agent.name(),
                    managed.config.model,
                    managed.session.state
                ),
            }
            if let Some(error) = state.as_ref().and_then(|state| state.last_error.as_deref()) {
                println!("last error: {error}");
            }
            if messages.is_empty() {
                println!("No messages");
            }
            if total > messages.len() {
                println!("({} older messages omitted)", total - messages.len());
            }
            for record in &messages {
                let summary = record
                    .error
                    .as_deref()
                    .or(record.result.as_deref())
                    .unwrap_or(record.text.as_str());
                let summary = summary.lines().next().unwrap_or_default();
                let (summary, truncated) = truncate_utf8(summary, 80);
                println!(
                    "{}\t{}\t{}\t{}\t{}{}",
                    record.id,
                    record.action.name(),
                    record.state.name(),
                    record.created_at,
                    summary,
                    if truncated { "…" } else { "" }
                );
            }
        }
    }
    Ok(())
}

/// Waits for a managed message's terminal result. Timeout is never success.
pub(crate) async fn wait_agent_message(
    globals: &Globals,
    message_id: &str,
    timeout: Duration,
    output: OutputFormat,
) -> anyhow::Result<()> {
    let message_id = canonical_uuid(message_id)?;
    if platform_host::wait(globals, &message_id, timeout, output).await? {
        return Ok(());
    }
    #[cfg(target_os = "linux")]
    if native_host::wait(globals, &message_id, timeout, output).await? {
        return Ok(());
    }
    let Some((environment, dir)) = find_message(&message_id)? else {
        #[cfg(target_os = "linux")]
        if native_host::recover_and_wait(globals, &message_id, timeout, output).await? {
            return Ok(());
        }
        anyhow::bail!("managed message {message_id} not found");
    };
    let (record, end) = wait_for_message(&environment, &dir, &message_id, timeout).await?;
    print_message_result(&record, output)?;
    match wait_failure(&record, &end).or_else(|| message_failure(&record)) {
        Some(failure) => Err(failure),
        None => Ok(()),
    }
}

async fn deliver_cli_message(
    managed: &ManagedConversation,
    record: MessageRecord,
) -> anyhow::Result<MessageRecord> {
    let client = host_session_client(&managed.environment).await?;
    if !create_message(&managed.dir, &record)? {
        anyhow::bail!("message ID {} already exists", record.id);
    }
    let id = record.id.clone();
    let line = control_line(&record.driver_id, &id)?;
    if let Err(error) = client.send_input(&record.target_session_id, line).await {
        let definitive = send_error_is_definitive(&error);
        let record = update_message(&managed.dir, &id, |r| {
            // The receiver's durable acceptance wins over a lost pipe ACK.
            apply_delivery_failure(r, definitive, &error.to_string());
        })?;
        if let Some(failure) = message_failure(&record) {
            return Err(failure);
        }
        if record.state.rank() < MessageState::Accepted.rank() {
            anyhow::bail!(
                "message {id} is {}: {}",
                record.state.name(),
                record.error.as_deref().unwrap_or("delivery failed")
            );
        }
        return await_acceptance(&managed.dir, &id).await;
    }
    update_message(&managed.dir, &id, |r| {
        r.transition(MessageState::PipeWritten);
    })?;
    await_acceptance(&managed.dir, &id).await
}

async fn await_acceptance(dir: &Path, id: &str) -> anyhow::Result<MessageRecord> {
    let deadline = Instant::now() + ACCEPT_TIMEOUT;
    loop {
        let record = load_message(dir, id)?;
        if record.decided() {
            return Ok(record);
        }
        if Instant::now() >= deadline {
            anyhow::bail!(
                "message {id} is {} and was not decided within {}s; it is not replayed automatically. Inspect it with `cw inbox` or `cw wait --message {id}`",
                record.state.name(),
                ACCEPT_TIMEOUT.as_secs()
            );
        }
        tokio::time::sleep(POLL_INTERVAL).await;
    }
}

enum WaitEnd {
    Terminal,
    TimedOut,
    SessionEnded(String),
}

async fn wait_for_message(
    environment: &HostEnvironment,
    dir: &Path,
    id: &str,
    timeout: Duration,
) -> anyhow::Result<(MessageRecord, WaitEnd)> {
    let deadline = Instant::now() + timeout;
    let mut next_session_check = Instant::now();
    loop {
        let record = load_message(dir, id)?;
        if record.state.is_terminal() {
            return Ok((record, WaitEnd::Terminal));
        }
        let current = Instant::now();
        if current >= deadline {
            return Ok((record, WaitEnd::TimedOut));
        }
        if current >= next_session_check {
            next_session_check = current + SESSION_CHECK_INTERVAL;
            if let Ok(session) = host_target(environment)
                .get(&record.target_session_id)
                .await
                && session_finished(&session)
            {
                // Reread so a final driver write is not misreported.
                let record = load_message(dir, id)?;
                let end = if record.state.is_terminal() {
                    WaitEnd::Terminal
                } else {
                    WaitEnd::SessionEnded(session.state)
                };
                return Ok((record, end));
            }
        }
        tokio::time::sleep(POLL_INTERVAL.min(deadline.saturating_duration_since(current))).await;
    }
}

fn wait_failure(record: &MessageRecord, end: &WaitEnd) -> Option<anyhow::Error> {
    match end {
        WaitEnd::Terminal => None,
        WaitEnd::TimedOut => Some(anyhow::anyhow!(
            "timed out waiting for message {}; it is still {} and its outcome is unknown, not success",
            record.id,
            record.state.name()
        )),
        WaitEnd::SessionEnded(state) => Some(anyhow::anyhow!(
            "the managed conversation session is {state}; message {} remains {} and its outcome is unknown until the conversation restarts",
            record.id,
            record.state.name()
        )),
    }
}

fn message_failure(record: &MessageRecord) -> Option<anyhow::Error> {
    let detail = record.error.as_deref().unwrap_or("no detail");
    match record.state {
        MessageState::Error => Some(anyhow::anyhow!("message {} failed: {detail}", record.id)),
        MessageState::Unknown => Some(anyhow::anyhow!(
            "message {} outcome is unknown: {detail}",
            record.id
        )),
        MessageState::Interrupted => Some(anyhow::anyhow!("message {} was interrupted", record.id)),
        _ => None,
    }
}

fn find_message(message_id: &str) -> anyhow::Result<Option<(HostEnvironment, PathBuf)>> {
    for environment in host_environments()? {
        let root = agents_root(&environment);
        let entries = match fs::read_dir(&root) {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error.into()),
        };
        existing_private_dir(&root)?;
        let mut found = None;
        for (count, entry) in entries.enumerate() {
            if count >= MAX_DRIVERS_SCANNED {
                anyhow::bail!(
                    "host environment {} has more than {MAX_DRIVERS_SCANNED} managed conversations",
                    environment.name
                );
            }
            let entry = entry?;
            let name = entry.file_name();
            let Some(driver_id) = name.to_str() else {
                continue;
            };
            if canonical_uuid(driver_id).is_err() {
                continue;
            }
            if fs::symlink_metadata(message_path(&entry.path(), message_id)).is_ok() {
                found = Some(driver_id.to_owned());
                break;
            }
        }
        if let Some(driver_id) = found {
            let dir = driver_dir(&environment, &driver_id)?;
            return Ok(Some((environment, dir)));
        }
    }
    Ok(None)
}

fn receiver_state(
    environment: &impl AgentStore,
    notification: &ParentNotification,
) -> Option<MessageState> {
    let dir = driver_dir(environment, &notification.parent_driver_id).ok()?;
    load_message(&dir, &notification.message_id)
        .ok()
        .map(|record| record.state)
}

fn message_view(environment: &impl AgentStore, record: &MessageRecord) -> Value {
    let mut value = serde_json::to_value(record).unwrap_or(Value::Null);
    if let Some(notification) = &record.notification {
        value["notification_receiver_state"] =
            json!(receiver_state(environment, notification).map(MessageState::name));
    }
    value
}

fn print_message_summary(record: &MessageRecord, output: OutputFormat) -> anyhow::Result<()> {
    match output {
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(record)?),
        OutputFormat::Text => {
            println!("{}\t{}", record.id, record.state.name());
            if let Some(error) = &record.error {
                eprintln!("{error}");
            }
        }
    }
    Ok(())
}

fn print_message_result(record: &MessageRecord, output: OutputFormat) -> anyhow::Result<()> {
    match output {
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(record)?),
        OutputFormat::Text => {
            match (&record.state, &record.result) {
                (MessageState::Completed, Some(result)) => println!("{result}"),
                _ => println!("{}\t{}", record.id, record.state.name()),
            }
            if record.result_truncated {
                eprintln!("(result truncated to {MAX_RESULT_BYTES} bytes)");
            }
            if let Some(error) = &record.error {
                eprintln!("{error}");
            }
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Driver process
// ---------------------------------------------------------------------------

#[derive(Debug, clap::Args)]
pub(crate) struct AgentDriverArgs {
    #[arg(long, help = "Host environment ID")]
    pub(crate) environment: String,
    #[arg(long, help = "Managed conversation driver ID")]
    pub(crate) driver_id: String,
    #[arg(long)]
    pub(crate) registry_root: Option<PathBuf>,
    #[cfg(target_os = "linux")]
    #[arg(long, conflicts_with = "registry_root")]
    pub(crate) guest_root: Option<PathBuf>,
}

pub(crate) async fn run_agent_driver(args: AgentDriverArgs) -> anyhow::Result<()> {
    run_agent_driver_inner(args, false).await
}
async fn run_agent_driver_inner(args: AgentDriverArgs, platform: bool) -> anyhow::Result<()> {
    // Records created before this process started can only name an earlier pipe.
    let started_at = now();
    let driver_id = canonical_uuid(&args.driver_id)?;
    canonical_uuid(&args.environment)?;
    #[cfg(target_os = "linux")]
    let guest_root = args.guest_root.as_ref();
    #[cfg(not(target_os = "linux"))]
    let guest_root: Option<&PathBuf> = None;
    let environment = match guest_root {
        Some(root) => {
            if !root.is_absolute() {
                anyhow::bail!("guest managed state root must be absolute");
            }
            existing_private_dir(root)?;
            DriverEnvironment::Guest {
                id: args.environment.clone(),
                root: root.clone(),
            }
        }
        None => DriverEnvironment::Host(match &args.registry_root {
            Some(registry) => host_environment_at(&registry.join(&args.environment))?,
            None => host_environment(&args.environment)?
                .context("the host environment for this managed conversation no longer exists")?,
        }),
    };
    if environment.id() != args.environment {
        anyhow::bail!("the agent driver requires the canonical environment ID");
    }
    let dir = driver_dir(&environment, &driver_id)?;
    #[cfg(target_os = "linux")]
    let platform_context = if platform {
        Some(platform_control::DriverContext::admit(
            &environment,
            &driver_id,
        )?)
    } else {
        anyhow::ensure!(
            platform_control::marker(&environment, &driver_id)?.is_none(),
            "platform driver requires its fixed private role"
        );
        None
    };
    #[cfg(not(target_os = "linux"))]
    anyhow::ensure!(!platform, "platform driver is Linux only");
    // Crash fence: one live driver per conversation; released by the kernel on exit.
    let _instance = StateLock::try_acquire(&dir.join("driver.lock"))?
        .context("another driver already owns this managed conversation")?;
    let config: AgentConfig = read_record(&dir.join("config.json"))?;
    config.validate(environment.id(), &driver_id)?;
    let binding = wait_for_binding(&dir, &driver_id).await?;
    let previous = read_optional::<DriverState>(&dir.join("state.json"))?
        .filter(|state| state.driver_id == driver_id && state.agent == config.agent);
    #[cfg(target_os = "linux")]
    if host_control::guardian_required(&environment, &driver_id)? && previous.is_some() {
        guest_peer::require_clean_previous(
            &dir,
            environment.id(),
            &driver_id,
            &binding.session_id,
        )?
        .context("previous guest peer custody is missing; restart is fenced")?;
    }
    let state = DriverState {
        version: 1,
        driver_id: driver_id.clone(),
        agent: config.agent,
        phase: DriverPhase::Starting,
        native_thread_id: previous
            .as_ref()
            .and_then(|state| state.native_thread_id.clone()),
        native_thread_established: previous
            .as_ref()
            .is_some_and(|state| state.native_thread_established),
        current_turn_id: None,
        active_message_id: None,
        queued: 0,
        capabilities: AgentCapabilities {
            steer: false,
            interrupt: false,
            note: "driver starting".into(),
        },
        policy: match (environment.host(), config.agent) {
            (Some(_), AgentKind::Codex) => CODEX_POLICY.into(),
            (Some(_), AgentKind::Claude) => CLAUDE_POLICY.into(),
            (None, _) => "native Linux VM execution: installed guest agent with the environment's selected typed provider projection; provider material remains outside the VM".into(),
        },
        last_error: None,
        started_at: started_at.clone(),
        updated_at: started_at.clone(),
    };
    let mut driver = Driver {
        #[cfg(target_os = "linux")]
        platform: platform_context,
        environment,
        dir,
        config,
        binding,
        state,
        started_at,
        queue: VecDeque::new(),
        active: None,
        pending: HashMap::new(),
        control_pending: HashMap::new(),
        settled: HashSet::new(),
    };
    driver.run().await
}

async fn wait_for_binding(dir: &Path, driver_id: &str) -> anyhow::Result<AgentBinding> {
    let deadline = Instant::now() + BINDING_TIMEOUT;
    loop {
        if let Some(binding) = read_optional::<AgentBinding>(&dir.join("binding.json"))? {
            if binding.driver_id != driver_id || binding.session_id.is_empty() {
                anyhow::bail!("managed conversation binding does not belong to driver {driver_id}");
            }
            return Ok(binding);
        }
        if Instant::now() >= deadline {
            anyhow::bail!(
                "the launching CLI did not bind this driver to its session within {}s; refusing to run unbound",
                BINDING_TIMEOUT.as_secs()
            );
        }
        tokio::time::sleep(POLL_INTERVAL).await;
    }
}

enum LineRead {
    Line,
    TooLong,
    Eof,
}

/// Reassembles one newline-delimited line from arbitrary read fragments.
async fn read_bounded_line<R: AsyncBufRead + Unpin>(
    reader: &mut R,
    max: usize,
    buf: &mut Vec<u8>,
) -> std::io::Result<LineRead> {
    buf.clear();
    let mut overflow = false;
    loop {
        let (consumed, complete) = {
            let available = reader.fill_buf().await?;
            if available.is_empty() {
                return Ok(if overflow {
                    LineRead::TooLong
                } else if buf.is_empty() {
                    LineRead::Eof
                } else {
                    LineRead::Line
                });
            }
            match available.iter().position(|byte| *byte == b'\n') {
                Some(end) => {
                    if !overflow && buf.len() + end <= max {
                        buf.extend_from_slice(&available[..end]);
                    } else {
                        overflow = true;
                        buf.clear();
                    }
                    (end + 1, true)
                }
                None => {
                    if !overflow && buf.len() + available.len() <= max {
                        buf.extend_from_slice(available);
                    } else {
                        overflow = true;
                        buf.clear();
                    }
                    (available.len(), false)
                }
            }
        };
        reader.consume(consumed);
        if complete {
            if overflow {
                return Ok(LineRead::TooLong);
            }
            if buf.last() == Some(&b'\r') {
                buf.pop();
            }
            return Ok(LineRead::Line);
        }
    }
}

enum NativeLine {
    Json(Value),
    Invalid(String),
    Closed(Option<String>),
}

async fn read_native_stdout(
    stdout: tokio::process::ChildStdout,
    events: tokio::sync::mpsc::Sender<NativeLine>,
) {
    let mut reader = tokio::io::BufReader::new(stdout);
    let mut buf = Vec::new();
    loop {
        let item = match read_bounded_line(&mut reader, MAX_NATIVE_LINE_BYTES, &mut buf).await {
            Ok(LineRead::Line) => {
                if buf.iter().all(u8::is_ascii_whitespace) {
                    continue;
                }
                match serde_json::from_slice(&buf) {
                    Ok(value) => NativeLine::Json(value),
                    Err(error) => NativeLine::Invalid(format!(
                        "ignored invalid JSON from the native agent: {error}"
                    )),
                }
            }
            Ok(LineRead::TooLong) => NativeLine::Invalid(format!(
                "ignored a native agent line over {MAX_NATIVE_LINE_BYTES} bytes"
            )),
            Ok(LineRead::Eof) => {
                let _ = events.send(NativeLine::Closed(None)).await;
                return;
            }
            Err(error) => {
                let _ = events
                    .send(NativeLine::Closed(Some(error.to_string())))
                    .await;
                return;
            }
        };
        if events.send(item).await.is_err() {
            return;
        }
    }
}

/// Native stderr is diagnostic only: forwarded, bounded, never parsed.
async fn forward_native_stderr(stderr: tokio::process::ChildStderr, label: &'static str) {
    let mut reader = tokio::io::BufReader::new(stderr);
    let mut buf = Vec::new();
    let mut forwarded = 0usize;
    let mut suppressed = false;
    loop {
        let read = match read_bounded_line(&mut reader, MAX_STDERR_LINE_BYTES, &mut buf).await {
            Ok(LineRead::Eof) | Err(_) => return,
            Ok(read) => read,
        };
        if forwarded >= MAX_STDERR_TOTAL_BYTES {
            if !suppressed {
                suppressed = true;
                eprintln!(
                    "[{label}] further stderr suppressed after {MAX_STDERR_TOTAL_BYTES} bytes"
                );
            }
            continue;
        }
        match read {
            LineRead::TooLong => {
                forwarded += MAX_STDERR_LINE_BYTES;
                eprintln!("[{label}] (stderr line over {MAX_STDERR_LINE_BYTES} bytes omitted)");
            }
            _ => {
                forwarded += buf.len();
                eprintln!("[{label}] {}", String::from_utf8_lossy(&buf));
            }
        }
    }
}

enum ControlInput {
    Line(Vec<u8>),
    Invalid(String),
}

/// Reads driver control lines on a detached thread so a blocked stdin read
/// never delays runtime shutdown.
fn spawn_control_reader() -> tokio::sync::mpsc::Receiver<ControlInput> {
    let (sender, receiver) = tokio::sync::mpsc::channel(64);
    std::thread::spawn(move || {
        let stdin = std::io::stdin();
        let mut reader = stdin.lock();
        loop {
            let mut buf = Vec::new();
            match (&mut reader)
                .take(MAX_CONTROL_LINE_BYTES as u64 + 1)
                .read_until(b'\n', &mut buf)
            {
                Ok(0) | Err(_) => return,
                Ok(_) => {}
            }
            let item = if buf.last() == Some(&b'\n') {
                buf.pop();
                if buf.last() == Some(&b'\r') {
                    buf.pop();
                }
                if buf.len() > MAX_CONTROL_LINE_BYTES {
                    ControlInput::Invalid("ignored an oversized control line".into())
                } else {
                    ControlInput::Line(buf)
                }
            } else if buf.len() > MAX_CONTROL_LINE_BYTES {
                // Discard the remainder of the oversized line.
                loop {
                    let mut rest = Vec::new();
                    match (&mut reader).take(64 * 1024).read_until(b'\n', &mut rest) {
                        Ok(0) | Err(_) => return,
                        Ok(_) if rest.last() == Some(&b'\n') => break,
                        Ok(_) => {}
                    }
                }
                ControlInput::Invalid("ignored an oversized control line".into())
            } else {
                ControlInput::Line(buf)
            };
            if matches!(&item, ControlInput::Line(line) if line.iter().all(u8::is_ascii_whitespace))
            {
                continue;
            }
            if sender.blocking_send(item).is_err() {
                return;
            }
        }
    });
    receiver
}

struct Peer {
    child: tokio::process::Child,
    stdin: tokio::process::ChildStdin,
    events: tokio::sync::mpsc::Receiver<NativeLine>,
    next_id: u64,
    #[cfg(target_os = "linux")]
    guest: Option<GuestPeer>,
}

#[cfg(target_os = "linux")]
struct GuestPeer {
    dir: PathBuf,
    identity: guest_peer::PeerIdentity,
}

impl Peer {
    fn has_guardian(&self) -> bool {
        #[cfg(target_os = "linux")]
        {
            self.guest.is_some()
        }
        #[cfg(not(target_os = "linux"))]
        {
            false
        }
    }

    fn spawn(
        program: &Path,
        args: &[&str],
        working_dir: &str,
        driver: &Driver,
        label: &'static str,
    ) -> anyhow::Result<Self> {
        #[cfg(target_os = "linux")]
        let guest =
            if host_control::guardian_required(&driver.environment, &driver.config.driver_id)? {
                Some(GuestPeer {
                    dir: driver.dir.clone(),
                    identity: guest_peer::prepare(
                        &driver.dir,
                        driver.environment.id(),
                        &driver.config.driver_id,
                        &driver.binding.session_id,
                        &driver.started_at,
                    )?,
                })
            } else {
                None
            };
        #[cfg(target_os = "linux")]
        let mut command = if let Some(guest) = &guest {
            let identity = &guest.identity;
            // Linux resolves this alias to the actual running ELF, including a
            // verified sealed memfd, rather than reopening a mutable pathname.
            let mut command = tokio::process::Command::new("/proc/self/exe");
            command.args([
                if driver.platform.is_some() {
                    "__platform-agent-peer"
                } else {
                    "_agent-peer"
                },
                "--environment",
                &identity.environment_id,
                "--driver-id",
                &identity.driver_id,
                "--session-id",
                &identity.session_id,
                "--instance-id",
                &identity.instance_id,
                "--driver-started-at",
                &identity.driver_started_at,
                "--driver-pid",
                &identity.driver_pid.to_string(),
                "--driver-start-ticks",
                &identity.driver_start_ticks.to_string(),
                "--guest-root",
                &driver.environment.root().to_string_lossy(),
                "--program",
                &program.to_string_lossy(),
            ]);
            if driver.environment.host().is_some() {
                command.arg("--host-member-custody");
            }
            command.arg("--");
            command
        } else {
            tokio::process::Command::new(program)
        };
        #[cfg(not(target_os = "linux"))]
        let mut command = tokio::process::Command::new(program);
        #[cfg(target_os = "linux")]
        if let Some(context) = &driver.platform {
            context.check(&driver.environment, &driver.config)?;
            command.args(context.arguments(args)).env_clear();
            for (name, value) in context.environment(&driver.dir)? {
                command.env(name, value);
            }
        } else {
            command.args(args);
        }
        #[cfg(not(target_os = "linux"))]
        command.args(args);
        command.current_dir(working_dir);
        let runtime_root = driver.environment.root();
        let registry_root = driver
            .environment
            .host()
            .and_then(|_| runtime_root.parent());
        if let Some(registry_root) = registry_root {
            command.env(HOST_DATA_DIR_ENV, registry_root);
        } else {
            command
                .env_remove(HOST_DATA_DIR_ENV)
                .env_remove("CW_CONFIG_DIR");
        }
        let mut child = command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            // A guest guardian retains custody after a driver crash or timeout.
            .kill_on_drop({
                #[cfg(target_os = "linux")]
                {
                    guest.is_none()
                }
                #[cfg(not(target_os = "linux"))]
                {
                    true
                }
            })
            .spawn()
            .with_context(|| format!("start the installed {label} CLI at {}", program.display()))?;
        let stdin = child.stdin.take().context("native agent stdin")?;
        let stdout = child.stdout.take().context("native agent stdout")?;
        let stderr = child.stderr.take().context("native agent stderr")?;
        let (sender, events) = tokio::sync::mpsc::channel(256);
        tokio::spawn(read_native_stdout(stdout, sender));
        tokio::spawn(forward_native_stderr(stderr, label));
        Ok(Self {
            child,
            stdin,
            events,
            next_id: 1,
            #[cfg(target_os = "linux")]
            guest,
        })
    }

    async fn send(&mut self, value: &Value) -> anyhow::Result<()> {
        let mut line = serde_json::to_vec(value)?;
        line.push(b'\n');
        tokio::time::timeout(NATIVE_WRITE_TIMEOUT, async {
            self.stdin
                .write_all(&line)
                .await
                .context("write to the native agent")?;
            self.stdin.flush().await.context("flush native agent input")
        })
        .await
        .context("native agent input write timed out; delivery is unknown")??;
        Ok(())
    }

    async fn request(&mut self, method: &str, params: Value) -> anyhow::Result<u64> {
        let id = self.next_id;
        self.next_id += 1;
        self.send(&json!({"id": id, "method": method, "params": params}))
            .await?;
        Ok(id)
    }

    /// Startup-only synchronous JSON-RPC call; the main loop is not running yet.
    async fn call(&mut self, method: &str, params: Value) -> anyhow::Result<Value> {
        let id = self.request(method, params).await?;
        let deadline = tokio::time::Instant::now() + NATIVE_RPC_TIMEOUT;
        loop {
            let line = tokio::time::timeout_at(deadline, self.events.recv())
                .await
                .map_err(|_| {
                    anyhow::anyhow!(
                        "native {method} did not answer within {}s",
                        NATIVE_RPC_TIMEOUT.as_secs()
                    )
                })?;
            match line {
                Some(NativeLine::Json(value)) => {
                    let request = value
                        .get("method")
                        .and_then(Value::as_str)
                        .map(str::to_owned);
                    match (request, value.get("id").cloned()) {
                        (None, Some(response)) if response.as_u64() == Some(id) => {
                            if let Some(error) = value.get("error") {
                                anyhow::bail!("native {method} failed: {}", rpc_error_text(error));
                            }
                            return Ok(value.get("result").cloned().unwrap_or(Value::Null));
                        }
                        (Some(request), Some(request_id)) => {
                            self.send(&codex_request_response(&request, request_id))
                                .await?;
                        }
                        _ => {}
                    }
                }
                Some(NativeLine::Invalid(reason)) => log(reason),
                Some(NativeLine::Closed(_)) | None => {
                    anyhow::bail!(
                        "the native agent exited during {method}; inspect its stderr above"
                    )
                }
            }
        }
    }

    async fn stop(&mut self) -> Option<std::process::ExitStatus> {
        #[cfg(target_os = "linux")]
        if let Some(guest) = &self.guest {
            let deadline = tokio::time::Instant::now() + STOP_GRACE;
            let mut status = None;
            loop {
                if let Ok(receipt) = guest_peer::read_receipt(&guest.dir, &guest.identity) {
                    if !receipt.cleanup_unknown && receipt.finished_at.is_some() {
                        return match status {
                            Some(status) => Some(status),
                            None => tokio::time::timeout(STOP_GRACE, self.child.wait())
                                .await
                                .ok()
                                .and_then(Result::ok),
                        };
                    }
                    // Signal only the recorded guardian process birth. A late
                    // guardian startup is retried within this bounded wait.
                    let _ = guest_peer::signal_guardian(&guest.dir, &guest.identity);
                }
                if status.is_none() {
                    status = self.child.try_wait().ok().flatten();
                }
                if tokio::time::Instant::now() >= deadline {
                    // Never SIGKILL the guardian; it continues owning cleanup.
                    return None;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        }
        if let Ok(Some(status)) = self.child.try_wait() {
            return Some(status);
        }
        let _ = self.stdin.shutdown().await;
        if let Ok(Ok(status)) = tokio::time::timeout(STOP_GRACE, self.child.wait()).await {
            return Some(status);
        }
        let _ = self.child.start_kill();
        tokio::time::timeout(STOP_GRACE, self.child.wait())
            .await
            .ok()
            .and_then(Result::ok)
    }
}

fn rpc_error_text(error: &Value) -> String {
    error
        .get("message")
        .and_then(Value::as_str)
        .map(str::to_owned)
        .unwrap_or_else(|| error.to_string())
}

/// The driver cannot answer approvals interactively; it declines them under
/// the recorded policy instead of leaving the native turn blocked.
fn codex_request_response(method: &str, id: Value) -> Value {
    log(format!(
        "declined native request {method} under policy: {CODEX_POLICY}"
    ));
    match method {
        "item/commandExecution/requestApproval" | "item/fileChange/requestApproval" => {
            json!({"id": id, "result": {"decision": "decline"}})
        }
        "execCommandApproval" | "applyPatchApproval" => {
            json!({"id": id, "result": {"decision": "denied"}})
        }
        _ => {
            json!({"id": id, "error": {"code": -32601, "message": format!("the Codewire driver does not handle {method}")}})
        }
    }
}

fn text_input(text: &str) -> Value {
    json!([{"type": "text", "text": text}])
}

fn turn_text(record: &MessageRecord) -> String {
    match &record.reply_to {
        Some(reply) => format!("[Codewire: in reply to message {reply}]\n{}", record.text),
        None => record.text.clone(),
    }
}

fn content_text(message: &Value) -> Option<String> {
    match message.pointer("/message/content")? {
        Value::String(text) => Some(text.clone()),
        Value::Array(items) => {
            let texts: Vec<&str> = items
                .iter()
                .filter(|item| item.get("type").and_then(Value::as_str) == Some("text"))
                .filter_map(|item| item.get("text").and_then(Value::as_str))
                .collect();
            (!texts.is_empty()).then(|| texts.join(""))
        }
        _ => None,
    }
}

enum Pending {
    TurnStart(String),
    Steer(String),
    Interrupt(String),
}

#[derive(Clone, Copy)]
enum TurnStatus {
    Completed,
    Interrupted,
    Failed,
}

impl TurnStatus {
    fn message_state(self) -> MessageState {
        match self {
            Self::Completed => MessageState::Completed,
            Self::Interrupted => MessageState::Interrupted,
            Self::Failed => MessageState::Error,
        }
    }
}

struct ActiveTurn {
    message_id: String,
    text: String,
    turn_id: Option<String>,
    texts: Vec<String>,
    steers: Vec<String>,
    interrupts: Vec<String>,
    usage: Option<Value>,
    acknowledged: bool,
}

fn control_targets_turn(record: &MessageRecord, active: &ActiveTurn) -> bool {
    record.expected_active_message_id.as_deref() == Some(active.message_id.as_str())
        && record
            .expected_turn_id
            .as_ref()
            .is_none_or(|expected| active.turn_id.as_ref() == Some(expected))
}

enum Decision {
    Ignore,
    Duplicate,
    Queue,
    Steer(String),
    Interrupt(Option<String>),
}

enum DriverEvent {
    Control(Option<ControlInput>),
    Native(Option<NativeLine>),
    Stop(&'static str),
    Adopt,
    ShutdownProbe,
}

enum StartupEvent {
    Initialized(anyhow::Result<()>),
    Stop(&'static str),
    #[cfg(target_os = "linux")]
    Shutdown(anyhow::Result<Box<native::ShutdownRecord>>),
}

#[cfg(target_os = "linux")]
async fn wait_startup_shutdown(
    dir: PathBuf,
    identity: Option<guest_peer::PeerIdentity>,
) -> anyhow::Result<native::ShutdownRecord> {
    let Some(identity) = identity else {
        return std::future::pending().await;
    };
    let mut probe = tokio::time::interval(Duration::from_millis(500));
    probe.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        probe.tick().await;
        if let Some(shutdown) = native::admit_shutdown(&dir, &identity)? {
            return Ok(shutdown);
        }
    }
}

struct Driver {
    #[cfg(target_os = "linux")]
    platform: Option<platform_control::DriverContext>,
    environment: DriverEnvironment,
    dir: PathBuf,
    config: AgentConfig,
    binding: AgentBinding,
    state: DriverState,
    started_at: String,
    queue: VecDeque<String>,
    active: Option<ActiveTurn>,
    pending: HashMap<u64, Pending>,
    control_pending: HashMap<String, String>,
    settled: HashSet<String>,
}

impl Driver {
    fn message_generations(&self) -> anyhow::Result<(Option<u64>, Option<u64>)> {
        #[cfg(target_os = "linux")]
        let platform = match &self.platform {
            Some(p) => {
                p.check(&self.environment, &self.config)?;
                Some(p.generation)
            }
            None => None,
        };
        #[cfg(not(target_os = "linux"))]
        let platform = None;
        Ok((self.member_generation()?, platform))
    }
    fn member_generation(&self) -> anyhow::Result<Option<u64>> {
        #[cfg(target_os = "linux")]
        {
            host_control::generation(&self.environment, &self.config.driver_id)
        }
        #[cfg(not(target_os = "linux"))]
        {
            Ok(None)
        }
    }
    fn persist_state(&mut self) -> anyhow::Result<()> {
        self.state.queued = self.queue.len();
        self.state.updated_at = now();
        write_private_json(&self.dir.join("state.json"), &self.state)
    }

    fn thread_id(&self) -> anyhow::Result<String> {
        self.state
            .native_thread_id
            .clone()
            .context("the native conversation has no thread ID")
    }

    async fn run(&mut self) -> anyhow::Result<()> {
        self.persist_state()?;
        self.recover().await?;
        let mut control = spawn_control_reader();
        let mut control_open = true;
        use tokio::signal::unix::{SignalKind, signal};
        let mut terminate = signal(SignalKind::terminate())?;
        let mut interrupt = signal(SignalKind::interrupt())?;
        let mut hangup = signal(SignalKind::hangup())?;
        // Keep the spawned peer outside the initialization future. Cancelling
        // a stalled protocol handshake must retain the guardian and its family
        // until cleanup is proved, just like shutdown during a running turn.
        let mut peer = match self.spawn_peer() {
            Ok(peer) => peer,
            Err(error) => return self.startup_failed(error).await,
        };
        let startup = {
            #[cfg(target_os = "linux")]
            let shutdown = wait_startup_shutdown(
                self.dir.clone(),
                peer.guest.as_ref().map(|guest| guest.identity.clone()),
            );
            let initialize = self.initialize_peer(&mut peer);
            #[cfg(target_os = "linux")]
            {
                tokio::select! {
                    biased;
                    shutdown = shutdown => StartupEvent::Shutdown(shutdown.map(Box::new)),
                    _ = terminate.recv() => StartupEvent::Stop("SIGTERM"),
                    _ = interrupt.recv() => StartupEvent::Stop("SIGINT"),
                    _ = hangup.recv() => StartupEvent::Stop("SIGHUP"),
                    result = initialize => StartupEvent::Initialized(result),
                }
            }
            #[cfg(not(target_os = "linux"))]
            {
                tokio::select! {
                    biased;
                    _ = terminate.recv() => StartupEvent::Stop("SIGTERM"),
                    _ = interrupt.recv() => StartupEvent::Stop("SIGINT"),
                    _ = hangup.recv() => StartupEvent::Stop("SIGHUP"),
                    result = initialize => StartupEvent::Initialized(result),
                }
            }
        };
        match startup {
            StartupEvent::Initialized(Ok(())) => {}
            StartupEvent::Initialized(Err(error)) => {
                let error = if peer.stop().await.is_some() {
                    error
                } else {
                    error.context("native startup cleanup is unknown; restart is fenced")
                };
                return self.startup_failed(error).await;
            }
            StartupEvent::Stop(signal) => {
                return self
                    .lose_peer(&mut peer, format!("startup stopped by {signal}"), true)
                    .await;
            }
            #[cfg(target_os = "linux")]
            StartupEvent::Shutdown(Ok(shutdown)) => {
                let result = self
                    .lose_peer(
                        &mut peer,
                        format!("managed startup shutdown {}", shutdown.operation_id),
                        true,
                    )
                    .await;
                let error = result.as_ref().err().map(|error| format!("{error:#}"));
                native::complete_shutdown(&self.dir, &shutdown, error.as_deref())?;
                return result;
            }
            #[cfg(target_os = "linux")]
            StartupEvent::Shutdown(Err(error)) => {
                return self
                    .lose_peer(
                        &mut peer,
                        format!("could not validate startup shutdown: {error:#}"),
                        false,
                    )
                    .await;
            }
        };
        self.state.phase = DriverPhase::Idle;
        self.persist_state()?;
        log(format!(
            "{} conversation ready (native thread {})",
            self.config.agent.name(),
            self.state.native_thread_id.as_deref().unwrap_or("-")
        ));
        let mut adopt = tokio::time::interval(ADOPT_SCAN_INTERVAL);
        adopt.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let mut shutdown_probe = tokio::time::interval(Duration::from_millis(500));
        loop {
            #[cfg(target_os = "linux")]
            if let Some(identity) = peer.guest.as_ref().map(|guest| guest.identity.clone()) {
                match native::admit_shutdown(&self.dir, &identity) {
                    Ok(Some(shutdown)) => {
                        let result = self
                            .lose_peer(
                                &mut peer,
                                format!("managed shutdown {}", shutdown.operation_id),
                                true,
                            )
                            .await;
                        let error = result.as_ref().err().map(|error| format!("{error:#}"));
                        native::complete_shutdown(&self.dir, &shutdown, error.as_deref())?;
                        return result;
                    }
                    Ok(None) => {}
                    Err(error) => {
                        return self
                            .lose_peer(
                                &mut peer,
                                format!("could not validate managed shutdown: {error:#}"),
                                false,
                            )
                            .await;
                    }
                }
            }
            if let Err(error) = self.start_next(&mut peer).await {
                return self
                    .lose_peer(
                        &mut peer,
                        format!("could not issue the next turn: {error:#}"),
                        false,
                    )
                    .await;
            }
            let event = tokio::select! {
                input = control.recv(), if control_open => DriverEvent::Control(input),
                line = peer.events.recv() => DriverEvent::Native(line),
                _ = terminate.recv() => DriverEvent::Stop("SIGTERM"),
                _ = interrupt.recv() => DriverEvent::Stop("SIGINT"),
                _ = hangup.recv() => DriverEvent::Stop("SIGHUP"),
                _ = adopt.tick() => DriverEvent::Adopt,
                _ = shutdown_probe.tick(), if peer.has_guardian() => DriverEvent::ShutdownProbe,
            };
            let result = match event {
                DriverEvent::Control(Some(ControlInput::Line(line))) => {
                    self.on_control(&mut peer, &line).await
                }
                DriverEvent::Control(Some(ControlInput::Invalid(reason))) => {
                    log(reason);
                    Ok(())
                }
                DriverEvent::Control(None) => {
                    control_open = false;
                    Ok(())
                }
                DriverEvent::Native(Some(NativeLine::Json(value))) => {
                    self.on_native(&mut peer, value).await
                }
                DriverEvent::Native(Some(NativeLine::Invalid(reason))) => {
                    log(reason);
                    Ok(())
                }
                DriverEvent::Native(Some(NativeLine::Closed(reason))) => {
                    let reason = reason
                        .map(|reason| format!(": {reason}"))
                        .unwrap_or_default();
                    return self
                        .lose_peer(
                            &mut peer,
                            format!("the native agent closed its output{reason}"),
                            false,
                        )
                        .await;
                }
                DriverEvent::Native(None) => {
                    return self
                        .lose_peer(&mut peer, "the native agent output ended".into(), false)
                        .await;
                }
                DriverEvent::Stop(signal) => {
                    return self
                        .lose_peer(
                            &mut peer,
                            format!("the driver was stopped by {signal}"),
                            true,
                        )
                        .await;
                }
                DriverEvent::Adopt => {
                    if let Err(error) = self.adopt_notifications().await {
                        log(format!("notification scan failed: {error:#}"));
                    }
                    Ok(())
                }
                DriverEvent::ShutdownProbe => Ok(()),
            };
            if let Err(error) = result {
                return self.lose_peer(&mut peer, format!("{error:#}"), false).await;
            }
        }
    }

    async fn startup_failed(&mut self, error: anyhow::Error) -> anyhow::Result<()> {
        self.state.phase = DriverPhase::Failed;
        let reason = truncate_utf8(&format!("{error:#}"), 128 * 1024).0;
        self.state.last_error = Some(reason.clone());
        while let Some(id) = self.queue.pop_front() {
            let record = update_message(&self.dir, &id, |record| {
                record.fail(
                    MessageState::Error,
                    format!("native agent startup failed before issuing this task: {reason}"),
                );
            })?;
            self.notify_parent(&record).await;
        }
        let _ = self.persist_state();
        Err(error)
    }

    fn spawn_peer(&mut self) -> anyhow::Result<Peer> {
        match self.config.agent {
            AgentKind::Codex => Peer::spawn(
                &self.config.program,
                &["app-server"],
                &self.config.working_dir,
                self,
                "codex",
            ),
            AgentKind::Claude => self.spawn_claude(),
        }
    }

    async fn initialize_peer(&mut self, peer: &mut Peer) -> anyhow::Result<()> {
        match self.config.agent {
            AgentKind::Codex => self.initialize_codex(peer).await,
            AgentKind::Claude => self.initialize_claude(peer).await,
        }
    }

    /// Restart fence: in-flight work becomes unknown; only provably unissued
    /// messages are kept. Nothing is retried.
    async fn recover(&mut self) -> anyhow::Result<()> {
        let initial = self.config.initial_message_id.clone();
        let started_at = self.started_at.clone();
        let generation = self.message_generations()?;
        let mut unknown = Vec::new();
        for id in ordered_message_ids(&self.dir)? {
            let record = load_message(&self.dir, &id)?;
            if record.state.is_terminal() {
                self.settled.insert(record.id.clone());
                // Repair the result outbox after a crash between completion
                // and parent delivery. Native turns are never replayed.
                if record.action.starts_turn() {
                    unknown.push(record.id);
                }
                continue;
            }
            if !managed_message_generation_matches(generation, &record) {
                let updated = update_message(&self.dir, &record.id, |r| {
                    r.fail(MessageState::Unknown,"the member incarnation changed; this message is retained and never replayed");
                })?;
                self.settled.insert(updated.id.clone());
                if updated.action.starts_turn() {
                    unknown.push(updated.id);
                }
                continue;
            }
            let pre_accept = record.state.rank() < MessageState::Accepted.rank();
            let adoptable = record.action == MessageAction::Notification
                || (initial.as_deref() == Some(record.id.as_str())
                    && record.state == MessageState::Requested);
            if pre_accept && !adoptable && record.created_at >= started_at {
                // Its delivery line may still be in this driver's pipe.
                continue;
            }
            let previous = record.state;
            let updated = update_message(&self.dir, &record.id, |r| match r.state {
                MessageState::Running => {
                    r.fail(
                        MessageState::Unknown,
                        "the driver restarted while this was in flight; outcome unknown; not replayed",
                    );
                }
                MessageState::Accepted if !r.action.starts_turn() => {
                    r.fail(
                        MessageState::Error,
                        "the driver restarted before this was issued; steering and interrupts are never replayed",
                    );
                }
                state if state.rank() < MessageState::Accepted.rank() && adoptable => {
                    r.transition(MessageState::Accepted);
                }
                state if state.rank() < MessageState::Accepted.rank() => {
                    r.fail(
                        MessageState::Error,
                        "the driver restarted before accepting this message; it was never sent to the agent; send it again explicitly",
                    );
                }
                _ => {}
            })?;
            match updated.state {
                MessageState::Accepted => {
                    self.settled.insert(updated.id.clone());
                    self.queue.push_back(updated.id);
                }
                MessageState::Unknown if previous == MessageState::Running => {
                    self.settled.insert(updated.id.clone());
                    unknown.push(updated.id);
                }
                state if state.is_terminal() => {
                    self.settled.insert(updated.id);
                }
                _ => {}
            }
        }
        self.persist_state()?;
        for id in unknown {
            let record = load_message(&self.dir, &id)?;
            self.notify_parent(&record).await;
        }
        Ok(())
    }

    /// Worker notifications are adopted from the inbox as well as the pipe; the
    /// single accepted transition keeps delivery at most once.
    async fn adopt_notifications(&mut self) -> anyhow::Result<()> {
        let mut adopted = false;
        let generation = self.message_generations()?;
        for id in message_ids(&self.dir)? {
            if self.settled.contains(&id) {
                continue;
            }
            let record = load_message(&self.dir, &id)?;
            if record.state.rank() >= MessageState::Accepted.rank() {
                self.settled.insert(id);
                continue;
            }
            if record.action != MessageAction::Notification
                || record.target_session_id != self.binding.session_id
            {
                continue;
            }
            if !managed_message_generation_matches(generation, &record) {
                update_message(&self.dir, &id, |r| {
                    r.fail(
                        MessageState::Unknown,
                        "the parent member incarnation changed; notification was not adopted",
                    );
                })?;
                self.settled.insert(id);
                continue;
            }
            let mut accepted = false;
            update_message(&self.dir, &id, |r| {
                accepted = r.transition(MessageState::Accepted)
            })?;
            self.settled.insert(id.clone());
            if accepted {
                log(format!("adopted notification {id} from the inbox"));
                self.queue.push_back(id);
                adopted = true;
            }
        }
        if adopted {
            self.persist_state()?;
        }
        Ok(())
    }

    async fn initialize_codex(&mut self, peer: &mut Peer) -> anyhow::Result<()> {
        peer.call(
            "initialize",
            json!({"clientInfo": {"name": "codewire", "title": "Codewire", "version": env!("CARGO_PKG_VERSION")}}),
        )
        .await?;
        peer.send(&json!({"method": "initialized"})).await?;
        let mut params = json!({
            "model": self.config.model,
            "cwd": self.config.working_dir,
            "approvalPolicy": "never",
            "sandbox": "danger-full-access",
        });
        let thread = match (
            &self.state.native_thread_id,
            self.state.native_thread_established,
        ) {
            (Some(thread), true) => {
                params["threadId"] = json!(thread);
                let result = peer.call("thread/resume", params).await.with_context(|| {
                    format!("resume Codex thread {thread}; the saved thread was not replaced")
                })?;
                let resumed = result
                    .pointer("/thread/id")
                    .and_then(Value::as_str)
                    .unwrap_or_default();
                if resumed != thread {
                    anyhow::bail!(
                        "Codex resumed thread {resumed:?} instead of saved thread {thread}"
                    );
                }
                thread.clone()
            }
            _ => {
                let result = peer.call("thread/start", params).await?;
                result
                    .pointer("/thread/id")
                    .and_then(Value::as_str)
                    .context("Codex thread/start returned no thread ID")?
                    .to_owned()
            }
        };
        self.state.native_thread_id = Some(thread);
        self.state.native_thread_established = true;
        self.state.capabilities = AgentCapabilities {
            steer: true,
            interrupt: true,
            note: "Codex app-server turn/steer with expectedTurnId and turn/interrupt".into(),
        };
        self.persist_state()?;
        Ok(())
    }

    fn spawn_claude(&mut self) -> anyhow::Result<Peer> {
        let saved = (
            self.state.native_thread_id.clone(),
            self.state.native_thread_established,
        );
        let (flag, session) = match saved {
            (Some(session), true) => ("--resume", session),
            (Some(session), false) => ("--session-id", session),
            (None, _) => {
                let session = uuid::Uuid::new_v4().to_string();
                self.state.native_thread_id = Some(session.clone());
                self.persist_state()?;
                ("--session-id", session)
            }
        };
        let mut args = vec![
            "-p",
            "--input-format",
            "stream-json",
            "--output-format",
            "stream-json",
            "--verbose",
            "--replay-user-messages",
            "--model",
            self.config.model.as_str(),
            flag,
            session.as_str(),
        ];
        if let Some(effort) = &self.config.effort {
            args.extend(["--effort", effort.as_str()]);
        }
        Peer::spawn(
            &self.config.program,
            &args,
            &self.config.working_dir,
            self,
            "claude",
        )
    }

    async fn initialize_claude(&mut self, peer: &mut Peer) -> anyhow::Result<()> {
        // Positive feature detection: advertise interrupt only after the
        // installed CLI answers the native control initialize request.
        let request_id = format!("cw-probe-{}", uuid::Uuid::new_v4());
        peer.send(&json!({"type": "control_request", "request_id": request_id, "request": {"subtype": "initialize"}}))
            .await?;
        let detected = match tokio::time::timeout(
            CONTROL_PROBE_TIMEOUT,
            claude_control_probe(peer, &request_id),
        )
        .await
        {
            Ok(result) => result?,
            Err(_) => false,
        };
        self.state.capabilities = AgentCapabilities {
            steer: false,
            interrupt: detected,
            note: if detected {
                "Claude stream-json has no qualified mid-turn steering; interrupt uses the native control request detected at startup".into()
            } else {
                "Claude stream-json has no qualified mid-turn steering, and the installed CLI did not confirm native control requests".into()
            },
        };
        self.persist_state()?;
        Ok(())
    }

    async fn start_next(&mut self, peer: &mut Peer) -> anyhow::Result<()> {
        while self.active.is_none() {
            let Some(id) = self.queue.pop_front() else {
                break;
            };
            let generation = self.message_generations()?;
            let mut issued = false;
            let record = update_message(&self.dir, &id, |r| {
                if r.state == MessageState::Accepted {
                    if managed_message_generation_matches(generation, r) {
                        issued = r.transition(MessageState::Running);
                    } else {
                        r.fail(
                            MessageState::Unknown,
                            "the member incarnation changed before issue; nothing was replayed",
                        );
                    }
                }
            })?;
            if !issued {
                continue;
            }
            let text = turn_text(&record);
            self.active = Some(ActiveTurn {
                message_id: record.id.clone(),
                text: text.clone(),
                turn_id: None,
                texts: Vec::new(),
                steers: Vec::new(),
                interrupts: Vec::new(),
                usage: None,
                acknowledged: false,
            });
            self.state.phase = DriverPhase::Busy;
            self.state.active_message_id = Some(record.id.clone());
            self.state.current_turn_id = None;
            self.persist_state()?;
            match self.config.agent {
                AgentKind::Codex => {
                    let thread = self.thread_id()?;
                    let request = peer
                        .request(
                            "turn/start",
                            json!({"threadId": thread, "input": text_input(&text), "effort": self.config.effort}),
                        )
                        .await?;
                    self.pending
                        .insert(request, Pending::TurnStart(record.id.clone()));
                }
                AgentKind::Claude => {
                    peer.send(&json!({
                        "type": "user",
                        "session_id": self.state.native_thread_id,
                        "parent_tool_use_id": null,
                        "message": {"role": "user", "content": text},
                    }))
                    .await?;
                }
            }
            log(format!("message {} running", record.id));
        }
        Ok(())
    }

    async fn on_control(&mut self, peer: &mut Peer, line: &[u8]) -> anyhow::Result<()> {
        let control: ControlLine = match serde_json::from_slice(line) {
            Ok(control) => control,
            Err(error) => {
                log(format!("ignored invalid control line: {error}"));
                return Ok(());
            }
        };
        if control.v != 1 || control.driver_id != self.config.driver_id {
            log("ignored a control line for another driver or protocol version");
            return Ok(());
        }
        let Ok(id) = canonical_uuid(&control.message_id) else {
            log("ignored a control line with an invalid message ID");
            return Ok(());
        };
        if matches!(control.op, ControlOp::Shutdown) {
            // Shutdown is admitted from its durable, instance-bound journal at
            // the top of the loop, also when the sending CLI was cancelled.
            return Ok(());
        }
        self.accept(peer, &id).await
    }

    async fn accept(&mut self, peer: &mut Peer, id: &str) -> anyhow::Result<()> {
        let session_id = self.binding.session_id.clone();
        let capabilities = self.state.capabilities.clone();
        let agent = self.config.agent;
        let generation = self.message_generations()?;
        let active = self
            .active
            .as_ref()
            .map(|a| (a.message_id.clone(), a.turn_id.clone()));
        let mut decision = Decision::Ignore;
        let record = match update_message(&self.dir, id, |r| {
            if r.state.rank() >= MessageState::Accepted.rank() {
                decision = Decision::Duplicate;
                return;
            }
            if !managed_message_generation_matches(generation, r) {
                r.fail(
                    MessageState::Unknown,
                    "the member message has no current birth proof; it was not adopted",
                );
                return;
            }
            if r.target_session_id != session_id {
                r.fail(
                    MessageState::Error,
                    "the message targets a different session binding",
                );
                return;
            }
            match r.action {
                MessageAction::Prompt | MessageAction::Message | MessageAction::Notification => {
                    r.transition(MessageState::Accepted);
                    decision = Decision::Queue;
                }
                MessageAction::Steer => match &active {
                    _ if !capabilities.steer => {
                        r.fail(
                            MessageState::Error,
                            format!("steering is not supported: {}", capabilities.note),
                        );
                    }
                    Some((message, Some(turn)))
                        if (generation.0.is_some() || generation.1.is_some())
                            && (r.expected_turn_id.as_ref() != Some(turn)
                                || r.expected_active_message_id.as_ref() != Some(message)) =>
                    {
                        r.fail(
                            MessageState::Error,
                            "the targeted member turn ended; nothing was steered",
                        );
                    }
                    // Refuse locally what the provider would refuse later.
                    Some((_, Some(turn)))
                        if r.expected_turn_id
                            .as_ref()
                            .is_some_and(|expected| expected != turn) =>
                    {
                        r.fail(
                            MessageState::Error,
                            "the targeted turn ended; nothing was steered",
                        );
                    }
                    Some((_, Some(turn))) => {
                        let expected = r.expected_turn_id.clone().unwrap_or_else(|| turn.clone());
                        r.transition(MessageState::Accepted);
                        r.transition(MessageState::Running);
                        decision = Decision::Steer(expected);
                    }
                    _ => {
                        r.fail(
                            MessageState::Error,
                            "no active turn to steer; steering is never queued",
                        );
                    }
                },
                MessageAction::Interrupt => match &active {
                    _ if !capabilities.interrupt => {
                        r.fail(
                            MessageState::Error,
                            format!("interrupt is not supported: {}", capabilities.note),
                        );
                    }
                    None => {
                        r.fail(MessageState::Error, "no active turn to interrupt");
                    }
                    Some((message, _))
                        if r.expected_active_message_id
                            .as_ref()
                            .is_some_and(|expected| expected != message) =>
                    {
                        r.fail(
                            MessageState::Error,
                            "the targeted turn already ended; nothing was interrupted",
                        );
                    }
                    Some((_, None)) if agent == AgentKind::Codex => {
                        r.fail(
                            MessageState::Error,
                            "the current turn has not reported its native ID yet; nothing was interrupted",
                        );
                    }
                    Some((_, turn))
                        if r.expected_turn_id.is_some() && r.expected_turn_id != *turn =>
                    {
                        r.fail(
                            MessageState::Error,
                            "the targeted turn already ended; nothing was interrupted",
                        );
                    }
                    Some((_, turn)) => {
                        r.transition(MessageState::Accepted);
                        r.transition(MessageState::Running);
                        decision = Decision::Interrupt(turn.clone());
                    }
                },
            }
        }) {
            Ok(record) => record,
            Err(error) => {
                log(format!("ignored delivery of message {id}: {error:#}"));
                return Ok(());
            }
        };
        match decision {
            Decision::Ignore => log(format!(
                "rejected message {id}: {}",
                record.error.as_deref().unwrap_or("not deliverable")
            )),
            Decision::Duplicate => log(format!("ignored duplicate delivery of message {id}")),
            Decision::Queue => {
                self.settled.insert(record.id.clone());
                self.queue.push_back(record.id);
                self.persist_state()?;
            }
            Decision::Steer(expected) => {
                let thread = self.thread_id()?;
                self.pending
                    .insert(peer.next_id, Pending::Steer(record.id.clone()));
                let request = peer
                    .request(
                        "turn/steer",
                        json!({"threadId": thread, "input": text_input(&turn_text(&record)), "expectedTurnId": expected}),
                    )
                    .await?;
                debug_assert!(self.pending.contains_key(&request));
            }
            Decision::Interrupt(turn) => match agent {
                AgentKind::Codex => {
                    let thread = self.thread_id()?;
                    self.pending
                        .insert(peer.next_id, Pending::Interrupt(record.id.clone()));
                    let request = peer
                        .request(
                            "turn/interrupt",
                            json!({"threadId": thread, "turnId": turn}),
                        )
                        .await?;
                    debug_assert!(self.pending.contains_key(&request));
                }
                AgentKind::Claude => {
                    let request_id = format!("cw-{}", record.id);
                    self.control_pending
                        .insert(request_id.clone(), record.id.clone());
                    peer.send(&json!({"type": "control_request", "request_id": request_id, "request": {"subtype": "interrupt"}}))
                        .await?;
                }
            },
        }
        Ok(())
    }

    async fn on_native(&mut self, peer: &mut Peer, value: Value) -> anyhow::Result<()> {
        match self.config.agent {
            AgentKind::Codex => self.on_codex(peer, value).await,
            AgentKind::Claude => self.on_claude(peer, value).await,
        }
    }

    fn record_turn(&mut self, message_id: &str, turn: &str) -> anyhow::Result<()> {
        update_message(&self.dir, message_id, |r| {
            r.turn_id = Some(turn.to_owned());
            r.native_acknowledged = true;
        })?;
        self.state.current_turn_id = Some(turn.to_owned());
        self.persist_state()
    }

    async fn on_codex(&mut self, peer: &mut Peer, value: Value) -> anyhow::Result<()> {
        let method = value
            .get("method")
            .and_then(Value::as_str)
            .map(str::to_owned);
        let id = value.get("id").cloned();
        match (method, id) {
            (Some(method), Some(id)) => peer.send(&codex_request_response(&method, id)).await,
            (Some(method), None) => {
                let params = value.get("params").cloned().unwrap_or(Value::Null);
                self.on_codex_notification(&method, params).await
            }
            (None, Some(id)) => self.on_codex_response(id, &value).await,
            (None, None) => {
                log("ignored a native line without method or id");
                Ok(())
            }
        }
    }

    async fn on_codex_response(&mut self, id: Value, value: &Value) -> anyhow::Result<()> {
        let Some(pending) = id.as_u64().and_then(|id| self.pending.remove(&id)) else {
            log(format!(
                "ignored a native response for unknown request {id}"
            ));
            return Ok(());
        };
        let error = value.get("error").map(rpc_error_text);
        let result = value.get("result").cloned().unwrap_or(Value::Null);
        match pending {
            Pending::TurnStart(message_id) => {
                let is_active = self
                    .active
                    .as_ref()
                    .is_some_and(|active| active.message_id == message_id);
                if let Some(error) = error {
                    if is_active {
                        return self
                            .finish_turn(
                                TurnStatus::Failed,
                                None,
                                Some(format!("Codex rejected turn/start: {error}")),
                                None,
                            )
                            .await;
                    }
                    update_message(&self.dir, &message_id, |r| {
                        r.fail(
                            MessageState::Error,
                            format!("Codex rejected turn/start: {error}"),
                        );
                    })?;
                    return Ok(());
                }
                let turn = result
                    .pointer("/turn/id")
                    .and_then(Value::as_str)
                    .map(str::to_owned);
                let started = match (turn, self.active.as_mut()) {
                    (Some(turn), Some(active)) if active.message_id == message_id => {
                        Some(active.turn_id.get_or_insert(turn).clone())
                    }
                    _ => None,
                };
                if let Some(turn) = started {
                    self.record_turn(&message_id, &turn)?;
                }
            }
            Pending::Steer(message_id) => {
                if let Some(error) = error {
                    update_message(&self.dir, &message_id, |r| {
                        r.fail(
                            MessageState::Error,
                            format!("Codex rejected the steer: {error}"),
                        );
                    })?;
                    return Ok(());
                }
                let turn = result
                    .get("turnId")
                    .and_then(Value::as_str)
                    .map(str::to_owned);
                let record = load_message(&self.dir, &message_id)?;
                let joined = match self.active.as_mut() {
                    Some(active)
                        if active.turn_id == record.expected_turn_id
                            && (turn.is_none() || active.turn_id == turn) =>
                    {
                        active.steers.push(message_id.clone());
                        true
                    }
                    _ => false,
                };
                update_message(&self.dir, &message_id, |r| {
                    r.turn_id = turn.clone();
                    r.native_acknowledged = true;
                    if !joined {
                        r.result =
                            Some("the steer was accepted for a turn that had already ended".into());
                        r.transition(MessageState::Completed);
                    }
                })?;
            }
            Pending::Interrupt(message_id) => {
                if let Some(error) = error {
                    update_message(&self.dir, &message_id, |r| {
                        r.fail(
                            MessageState::Error,
                            format!("Codex rejected the interrupt: {error}"),
                        );
                    })?;
                    return Ok(());
                }
                let record = load_message(&self.dir, &message_id)?;
                match self.active.as_mut() {
                    Some(active) if control_targets_turn(&record, active) => {
                        active.interrupts.push(message_id.clone())
                    }
                    _ => {
                        update_message(&self.dir, &message_id, |r| {
                            r.result = Some("the turn had already ended".into());
                            r.transition(MessageState::Completed);
                        })?;
                        return Ok(());
                    }
                }
                update_message(&self.dir, &message_id, |r| r.native_acknowledged = true)?;
            }
        }
        Ok(())
    }

    async fn on_codex_notification(&mut self, method: &str, params: Value) -> anyhow::Result<()> {
        if matches!(
            method,
            "turn/started" | "turn/completed" | "item/completed" | "thread/tokenUsage/updated"
        ) && params.get("threadId").and_then(Value::as_str)
            != self.state.native_thread_id.as_deref()
        {
            log(format!("ignored {method} for another native thread"));
            return Ok(());
        }
        match method {
            "turn/started" => {
                let turn = params
                    .pointer("/turn/id")
                    .and_then(Value::as_str)
                    .map(str::to_owned);
                let started = match (turn, self.active.as_mut()) {
                    (Some(turn), Some(active)) if active.turn_id.is_none() => {
                        active.turn_id = Some(turn.clone());
                        Some((active.message_id.clone(), turn))
                    }
                    _ => None,
                };
                if let Some((message_id, turn)) = started {
                    self.record_turn(&message_id, &turn)?;
                }
            }
            "item/completed" => {
                if params.pointer("/item/type").and_then(Value::as_str) == Some("agentMessage")
                    && let Some(text) = params.pointer("/item/text").and_then(Value::as_str)
                    && let Some(active) = self.active.as_mut()
                {
                    let turn = params.get("turnId").and_then(Value::as_str);
                    if turn.is_none()
                        || active.turn_id.is_none()
                        || active.turn_id.as_deref() == turn
                    {
                        active.texts.clear();
                        active.texts.push(text.to_owned());
                    }
                }
            }
            "thread/tokenUsage/updated" => {
                if let Some(active) = self.active.as_mut() {
                    active.usage = params.get("tokenUsage").cloned();
                }
            }
            "turn/completed" => {
                let turn = params
                    .pointer("/turn/id")
                    .and_then(Value::as_str)
                    .map(str::to_owned);
                let Some(active) = self.active.as_mut() else {
                    log(format!(
                        "ignored turn/completed for {turn:?} without an active turn"
                    ));
                    return Ok(());
                };
                if let (Some(expected), Some(turn)) = (&active.turn_id, &turn)
                    && expected != turn
                {
                    log(format!(
                        "ignored turn/completed for turn {turn}; the active turn is {expected}"
                    ));
                    return Ok(());
                }
                if active.turn_id.is_none() {
                    active.turn_id = turn;
                }
                let result = active.texts.last().cloned();
                let usage = active.usage.clone();
                let native_error = params
                    .pointer("/turn/error/message")
                    .and_then(Value::as_str)
                    .map(str::to_owned);
                let (status, error) = match params.pointer("/turn/status").and_then(Value::as_str) {
                    Some("completed") => (TurnStatus::Completed, None),
                    Some("interrupted") => (TurnStatus::Interrupted, native_error),
                    Some("failed") => (
                        TurnStatus::Failed,
                        Some(
                            native_error
                                .unwrap_or_else(|| "Codex reported that the turn failed".into()),
                        ),
                    ),
                    other => (
                        TurnStatus::Failed,
                        Some(format!(
                            "Codex ended the turn with unrecognized status {other:?}"
                        )),
                    ),
                };
                self.finish_turn(status, result, error, usage).await?;
            }
            "error" => log(format!(
                "Codex reported: {}",
                params
                    .pointer("/error/message")
                    .and_then(Value::as_str)
                    .unwrap_or("unspecified error")
            )),
            _ => {}
        }
        Ok(())
    }

    async fn on_claude(&mut self, peer: &mut Peer, value: Value) -> anyhow::Result<()> {
        if let Some(session) = value.get("session_id").and_then(Value::as_str)
            && self.state.native_thread_id.as_deref() != Some(session)
        {
            anyhow::bail!(
                "Claude reported a different conversation ID; the saved conversation was not replaced"
            );
        }
        match value
            .get("type")
            .and_then(Value::as_str)
            .unwrap_or_default()
        {
            "system" => {
                if value.get("subtype").and_then(Value::as_str) == Some("init")
                    && let Some(session) = value.get("session_id").and_then(Value::as_str)
                {
                    debug_assert_eq!(self.state.native_thread_id.as_deref(), Some(session));
                    self.state.native_thread_established = true;
                    self.persist_state()?;
                }
            }
            "user" => {
                let replay = content_text(&value);
                let acknowledged = match self.active.as_mut() {
                    Some(active)
                        if !active.acknowledged
                            && replay.as_deref() == Some(active.text.as_str()) =>
                    {
                        active.acknowledged = true;
                        Some(active.message_id.clone())
                    }
                    _ => None,
                };
                if let Some(message_id) = acknowledged {
                    update_message(&self.dir, &message_id, |r| r.native_acknowledged = true)?;
                }
            }
            "assistant" => {
                if let Some(text) = content_text(&value)
                    && let Some(active) = self.active.as_mut()
                {
                    active.texts.clear();
                    active.texts.push(text);
                }
            }
            "result" => {
                let Some(active) = self.active.as_ref() else {
                    log("ignored a Claude result without an active turn");
                    return Ok(());
                };
                let subtype = value
                    .get("subtype")
                    .and_then(Value::as_str)
                    .unwrap_or("unknown");
                let is_error = value
                    .get("is_error")
                    .and_then(Value::as_bool)
                    .unwrap_or(subtype != "success");
                let text = value
                    .get("result")
                    .and_then(Value::as_str)
                    .map(str::to_owned)
                    .or_else(|| active.texts.last().cloned());
                let usage = json!({
                    "usage": value.get("usage"),
                    "total_cost_usd": value.get("total_cost_usd"),
                    "duration_ms": value.get("duration_ms"),
                    "num_turns": value.get("num_turns"),
                });
                let (status, error) = if subtype == "success" && !is_error {
                    (TurnStatus::Completed, None)
                } else if !active.interrupts.is_empty() {
                    (TurnStatus::Interrupted, None)
                } else {
                    let errors = value
                        .get("errors")
                        .and_then(Value::as_array)
                        .map(|errors| {
                            errors
                                .iter()
                                .filter_map(Value::as_str)
                                .collect::<Vec<_>>()
                                .join("; ")
                        })
                        .filter(|errors| !errors.is_empty());
                    let detail = errors.or_else(|| text.clone()).unwrap_or_default();
                    (
                        TurnStatus::Failed,
                        Some(format!("Claude ended the turn with {subtype}: {detail}")),
                    )
                };
                self.finish_turn(status, text, error, Some(usage)).await?;
            }
            "control_response" => {
                let response = value.get("response").cloned().unwrap_or(Value::Null);
                let Some(request_id) = response.get("request_id").and_then(Value::as_str) else {
                    return Ok(());
                };
                let Some(message_id) = self.control_pending.remove(request_id) else {
                    return Ok(());
                };
                if response.get("subtype").and_then(Value::as_str) == Some("success") {
                    let record = load_message(&self.dir, &message_id)?;
                    match self.active.as_mut() {
                        Some(active) if control_targets_turn(&record, active) => {
                            active.interrupts.push(message_id.clone());
                            update_message(&self.dir, &message_id, |r| {
                                r.native_acknowledged = true
                            })?;
                        }
                        _ => {
                            update_message(&self.dir, &message_id, |r| {
                                r.result = Some("the turn had already ended".into());
                                r.transition(MessageState::Completed);
                            })?;
                        }
                    }
                } else {
                    let error = response
                        .get("error")
                        .and_then(Value::as_str)
                        .unwrap_or("rejected")
                        .to_owned();
                    update_message(&self.dir, &message_id, |r| {
                        r.fail(
                            MessageState::Error,
                            format!("Claude rejected the interrupt: {error}"),
                        );
                    })?;
                }
            }
            "control_request" => {
                let request_id = value.get("request_id").cloned().unwrap_or(Value::Null);
                let subtype = value
                    .pointer("/request/subtype")
                    .and_then(Value::as_str)
                    .unwrap_or("unknown");
                log(format!("declined Claude control request {subtype}"));
                peer.send(&json!({
                    "type": "control_response",
                    "response": {
                        "subtype": "error",
                        "request_id": request_id,
                        "error": format!("the Codewire driver does not handle {subtype}"),
                    },
                }))
                .await?;
            }
            _ => {}
        }
        Ok(())
    }

    async fn finish_turn(
        &mut self,
        status: TurnStatus,
        result: Option<String>,
        error: Option<String>,
        usage: Option<Value>,
    ) -> anyhow::Result<()> {
        let Some(active) = self.active.take() else {
            return Ok(());
        };
        let state = status.message_state();
        let (result, truncated) = match result {
            Some(result) => {
                let (result, truncated) = truncate_utf8(&result, MAX_RESULT_BYTES);
                (Some(result), truncated)
            }
            None => (None, false),
        };
        let turn_id = active.turn_id.clone();
        let main = update_message(&self.dir, &active.message_id, |r| {
            if turn_id.is_some() {
                r.turn_id = turn_id.clone();
            }
            r.result = result.clone();
            r.result_truncated = truncated;
            r.usage = usage.clone();
            if let Some(error) = &error {
                r.error = Some(error.clone());
            }
            r.transition(state);
        })?;
        for steer in &active.steers {
            update_message(&self.dir, steer, |r| {
                r.result = result.clone();
                r.result_truncated = truncated;
                if let Some(error) = &error {
                    r.error = Some(error.clone());
                }
                r.transition(state);
            })?;
        }
        for interrupt in &active.interrupts {
            update_message(&self.dir, interrupt, |r| {
                r.result = Some(format!(
                    "turn {} ended as {}",
                    turn_id.as_deref().unwrap_or(active.message_id.as_str()),
                    state.name()
                ));
                r.transition(MessageState::Completed);
            })?;
        }
        self.state.phase = DriverPhase::Idle;
        self.state.active_message_id = None;
        self.state.current_turn_id = None;
        self.persist_state()?;
        log(format!("message {} {}", main.id, main.state.name()));
        self.notify_parent(&main).await;
        Ok(())
    }

    async fn lose_peer(
        &mut self,
        peer: &mut Peer,
        reason: String,
        stopping: bool,
    ) -> anyhow::Result<()> {
        let status = peer.stop().await;
        let cleanup_confirmed = status.is_some();
        let reason = match status {
            Some(status) => format!("{reason} (native agent {status})"),
            None => format!("{reason}; native peer cleanup is unknown; restart is fenced"),
        };
        let mut issued: Vec<String> = self
            .pending
            .drain()
            .filter_map(|(_, pending)| match pending {
                Pending::Steer(id) | Pending::Interrupt(id) => Some(id),
                Pending::TurnStart(_) => None,
            })
            .collect();
        issued.extend(self.control_pending.drain().map(|(_, id)| id));
        let active = self.active.take();
        if let Some(active) = &active {
            issued.extend(active.steers.iter().cloned());
            issued.extend(active.interrupts.iter().cloned());
        }
        for id in issued {
            if let Err(error) = update_message(&self.dir, &id, |r| {
                r.fail(MessageState::Unknown, reason.clone());
            }) {
                log(format!(
                    "could not record message {id} as unknown: {error:#}"
                ));
            }
        }
        if let Some(active) = active {
            match update_message(&self.dir, &active.message_id, |r| {
                r.fail(
                    MessageState::Unknown,
                    format!("{reason}; the turn outcome is unknown and is not replayed"),
                );
            }) {
                Ok(record) => self.notify_parent(&record).await,
                Err(error) => log(format!(
                    "could not record message {} as unknown: {error:#}",
                    active.message_id
                )),
            }
        }
        // Queued messages were never issued; they stay accepted for the next start.
        self.state.phase = if stopping && cleanup_confirmed {
            DriverPhase::Stopped
        } else {
            DriverPhase::Failed
        };
        self.state.last_error = (!stopping || !cleanup_confirmed).then(|| reason.clone());
        self.state.active_message_id = None;
        self.state.current_turn_id = None;
        if let Err(error) = self.persist_state() {
            log(format!("could not persist driver state: {error:#}"));
        }
        log(&reason);
        if stopping && cleanup_confirmed {
            Ok(())
        } else {
            Err(anyhow::anyhow!(reason))
        }
    }

    fn notification_text(&self, source: &MessageRecord) -> String {
        let who = if self.config.name.is_empty() {
            format!("session {}", self.binding.session_id)
        } else {
            format!("{} (session {})", self.config.name, self.binding.session_id)
        };
        let header = format!(
            "[Codewire] Managed worker {who} finished message {} as {}.",
            source.id,
            source.state.name()
        );
        let footer = format!(
            "Follow up with: cw msg {} {} \"...\" --reply-to {}",
            self.environment.id(),
            self.binding.session_id,
            source.id
        );
        let body = match source.state {
            MessageState::Completed => source
                .result
                .clone()
                .unwrap_or_else(|| "(the worker produced no reply text)".into()),
            _ => source
                .error
                .clone()
                .or_else(|| source.result.clone())
                .unwrap_or_default(),
        };
        let budget = MAX_TEXT_BYTES.saturating_sub(header.len() + footer.len() + 32);
        let (body, truncated) = truncate_utf8(&body, budget);
        format!(
            "{header}\n\n{body}{}\n\n{footer}",
            if truncated { "\n[truncated]" } else { "" }
        )
    }

    fn set_notification(
        &self,
        source_id: &str,
        notification: &ParentNotification,
        state: NotificationState,
        detail: Option<String>,
    ) -> anyhow::Result<()> {
        update_message(&self.dir, source_id, |r| {
            let mut notification = notification.clone();
            notification.state = state;
            notification.detail = detail;
            notification.updated_at = now();
            r.notification = Some(notification);
        })?;
        Ok(())
    }

    async fn notify_parent(&mut self, source: &MessageRecord) {
        if let Err(error) = self.try_notify_parent(source).await {
            log(format!(
                "parent notification for message {} failed: {error:#}",
                source.id
            ));
            if let Some(parent) = &self.config.parent {
                let notification = ParentNotification {
                    message_id: notification_id(&source.id),
                    parent_session_id: parent.session_id.clone(),
                    parent_driver_id: parent.driver_id.clone(),
                    state: NotificationState::Error,
                    detail: None,
                    updated_at: now(),
                };
                let _ = self.set_notification(
                    &source.id,
                    &notification,
                    NotificationState::Error,
                    Some(format!("{error:#}")),
                );
            }
        }
    }

    async fn try_notify_parent(&mut self, source: &MessageRecord) -> anyhow::Result<()> {
        let Some(parent) = self.config.parent.clone() else {
            return Ok(());
        };
        if !source.action.starts_turn() || !source.state.is_terminal() {
            return Ok(());
        }
        if let Some(current) = self.member_generation()? {
            anyhow::ensure!(
                source
                    .member_launch_generation
                    .is_some_and(|g| g > 0 && g <= current),
                "member child result has no original birth proof"
            );
        }
        let notification = ParentNotification {
            message_id: notification_id(&source.id),
            parent_session_id: parent.session_id.clone(),
            parent_driver_id: parent.driver_id.clone(),
            state: NotificationState::Pending,
            detail: None,
            updated_at: now(),
        };
        let parent_dir = driver_dir(&self.environment, &parent.driver_id)?;
        #[cfg(target_os = "linux")]
        host_control::admit_parent_notification(
            &self.environment,
            &self.config.driver_id,
            &parent.driver_id,
        )?;
        #[cfg(target_os = "linux")]
        let platform_parent = platform_control::parent_generation(
            &self.environment,
            &self.config.driver_id,
            &parent.driver_id,
        )?;
        #[cfg(target_os = "linux")]
        if let Some(context) = &self.platform {
            anyhow::ensure!(
                source
                    .platform_launch_generation
                    .is_some_and(|g| g > 0 && g <= context.generation)
                    && source.member_launch_generation.is_none(),
                "platform child result has no original generation"
            );
        }
        // Deliver only to the canonical parent bound at launch; never via aliases.
        let binding: AgentBinding = read_record(&parent_dir.join("binding.json"))?;
        if binding.driver_id != parent.driver_id || binding.session_id != parent.session_id {
            anyhow::bail!(
                "the parent conversation binding changed; the notification was not redirected"
            );
        }
        let mut record = MessageRecord::new(
            &parent.driver_id,
            &parent.session_id,
            MessageAction::Notification,
            self.notification_text(source),
        );
        record.id = notification.message_id.clone();
        #[cfg(target_os = "linux")]
        {
            record.member_launch_generation = host_control::parent_generation(
                &self.environment,
                &self.config.driver_id,
                &parent.driver_id,
            )?;
            record.platform_launch_generation = platform_parent;
        }
        record.source = Some(MessageSource {
            session_id: self.binding.session_id.clone(),
            driver_id: self.config.driver_id.clone(),
            message_id: source.id.clone(),
        });
        if !create_message(&parent_dir, &record)? {
            self.set_notification(
                &source.id,
                &notification,
                NotificationState::Pending,
                Some(
                    "created by an earlier driver run; the parent adopts it from its inbox".into(),
                ),
            )?;
            return Ok(());
        }
        self.set_notification(&source.id, &notification, NotificationState::Pending, None)?;
        #[cfg(target_os = "linux")]
        if self.member_generation()?.is_some() {
            // The target-owned parent adopts this original-birth notification
            // from its inbox. Never start/contact a daemon from a member driver
            // or confuse durable queueing with pipe/native acceptance.
            self.set_notification(
                &source.id,
                &notification,
                NotificationState::Pending,
                Some(
                    "queued in the canonical member parent inbox; adoption remains pending".into(),
                ),
            )?;
            return Ok(());
        }
        let Some(environment) = self.environment.host() else {
            self.set_notification(
                &source.id,
                &notification,
                NotificationState::Pending,
                Some(
                    "queued in the canonical parent inbox; the guest parent adopts it when ready"
                        .into(),
                ),
            )?;
            return Ok(());
        };
        let parent_view = host_target(environment).get(&parent.session_id).await;
        let parent_state = match &parent_view {
            Ok(view) if session_running(view) => None,
            Ok(view) => Some(view.state.clone()),
            Err(error) => Some(format!("unavailable ({error:#})")),
        };
        if let Some(parent_state) = parent_state {
            update_message(&parent_dir, &record.id, |r| {
                r.transition(MessageState::Undelivered);
            })?;
            self.set_notification(
                &source.id,
                &notification,
                NotificationState::Undelivered,
                Some(format!(
                    "parent session is {parent_state}; the parent conversation adopts the notification when it runs again"
                )),
            )?;
            return Ok(());
        }
        let line = control_line(&parent.driver_id, &record.id)?;
        let sent = match host_session_client(environment).await {
            Ok(client) => client
                .send_input(&parent.session_id, line)
                .await
                .map_err(|error| {
                    let definitive = send_error_is_definitive(&error);
                    (definitive, error.to_string())
                }),
            Err(error) => Err((true, format!("{error:#}"))),
        };
        match sent {
            Ok(()) => {
                update_message(&parent_dir, &record.id, |r| {
                    r.transition(MessageState::PipeWritten);
                })?;
                self.set_notification(
                    &source.id,
                    &notification,
                    NotificationState::PipeWritten,
                    None,
                )?;
            }
            Err((true, error)) => {
                update_message(&parent_dir, &record.id, |r| {
                    r.transition(MessageState::Undelivered);
                })?;
                self.set_notification(
                    &source.id,
                    &notification,
                    NotificationState::Undelivered,
                    Some(format!(
                        "not delivered ({error}); the parent adopts it from its inbox"
                    )),
                )?;
            }
            Err((false, error)) => {
                // The pipe line is never resent. The parent's single accepted
                // transition still admits the persisted record at most once.
                self.set_notification(
                    &source.id,
                    &notification,
                    NotificationState::Unknown,
                    Some(format!("pipe write outcome unknown ({error}); not resent")),
                )?;
            }
        }
        Ok(())
    }
}

async fn claude_control_probe(peer: &mut Peer, request_id: &str) -> anyhow::Result<bool> {
    loop {
        match peer.events.recv().await {
            Some(NativeLine::Json(value)) => {
                if value.get("type").and_then(Value::as_str) == Some("control_response")
                    && value
                        .pointer("/response/request_id")
                        .and_then(Value::as_str)
                        == Some(request_id)
                {
                    return Ok(value.pointer("/response/subtype").and_then(Value::as_str)
                        == Some("success"));
                }
            }
            Some(NativeLine::Invalid(reason)) => log(reason),
            Some(NativeLine::Closed(_)) | None => {
                anyhow::bail!(
                    "the installed Claude CLI exited during startup; inspect its stderr above"
                )
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn effort_uses_native_provider_levels_and_preserves_configured_claude_default() {
        assert_eq!(
            agent_effort(AgentKind::Codex, None).unwrap(),
            Some("max".into())
        );
        assert_eq!(agent_effort(AgentKind::Claude, None).unwrap(), None);
        assert_eq!(
            agent_effort(AgentKind::Claude, Some("xhigh")).unwrap(),
            Some("xhigh".into())
        );
        assert!(agent_effort(AgentKind::Claude, Some("ultra")).is_err());
    }

    #[test]
    fn lost_pipe_ack_preserves_receiver_acceptance_and_completion() {
        for state in [MessageState::Accepted, MessageState::Running] {
            let mut record =
                MessageRecord::new("driver", "session", MessageAction::Message, "task".into());
            record.transition(state);
            apply_delivery_failure(&mut record, false, "lost ACK");
            assert_eq!(record.state, state);
            assert!(record.transition(MessageState::Completed));
            assert!(record.error.is_none());
            apply_delivery_failure(&mut record, false, "late lost ACK");
            assert_eq!(record.state, MessageState::Completed);
            assert!(message_failure(&record).is_none());
        }
        let mut unaccepted =
            MessageRecord::new("driver", "session", MessageAction::Message, "task".into());
        apply_delivery_failure(&mut unaccepted, false, "lost ACK");
        assert_eq!(unaccepted.state, MessageState::Unknown);
        assert!(!unaccepted.transition(MessageState::Accepted));
    }

    #[test]
    fn provider_decides_steer_and_interrupt_but_the_driver_decides_a_message() {
        let mut message =
            MessageRecord::new("driver", "session", MessageAction::Message, "task".into());
        assert!(!message.decided());
        message.transition(MessageState::Accepted);
        assert!(message.decided());
        for action in [MessageAction::Steer, MessageAction::Interrupt] {
            let mut control = MessageRecord::new("driver", "session", action, String::new());
            control.transition(MessageState::Accepted);
            control.transition(MessageState::Running);
            assert!(!control.decided(), "driver admission alone decides nothing");
            let mut rejected = control.clone();
            rejected.fail(MessageState::Error, "Codex rejected the steer");
            assert!(rejected.decided() && message_failure(&rejected).is_some());
            control.native_acknowledged = true;
            assert!(control.decided() && message_failure(&control).is_none());
        }
    }

    #[test]
    fn post_write_failed_precondition_is_ambiguous_and_never_retried() {
        let status = codewire_daemon::client::SessionClientError::Status(
            tonic::Status::failed_precondition("stdin ACK lost"),
        );
        assert!(!send_error_is_definitive(&status));
    }

    #[test]
    fn late_interrupt_ack_cannot_attach_to_the_next_message_or_native_turn() {
        let mut record =
            MessageRecord::new("driver", "session", MessageAction::Interrupt, String::new());
        record.expected_active_message_id = Some("old-message".into());
        record.expected_turn_id = Some("old-turn".into());
        let mut active = ActiveTurn {
            message_id: "old-message".into(),
            text: String::new(),
            turn_id: Some("old-turn".into()),
            texts: Vec::new(),
            steers: Vec::new(),
            interrupts: Vec::new(),
            usage: None,
            acknowledged: true,
        };
        assert!(control_targets_turn(&record, &active));
        active.message_id = "next-message".into();
        assert!(!control_targets_turn(&record, &active));
        active.message_id = "old-message".into();
        active.turn_id = Some("next-turn".into());
        assert!(!control_targets_turn(&record, &active));
        record.expected_turn_id = None; // Claude identity is the original message.
        active.message_id = "next-message".into();
        assert!(!control_targets_turn(&record, &active));
    }

    #[test]
    fn oversized_native_outcome_remains_readable_after_atomic_persistence() {
        let temporary = tempfile::tempdir().unwrap();
        let driver = uuid::Uuid::new_v4().to_string();
        let dir = temporary.path().join(&driver);
        private_directory(&dir).unwrap();
        private_directory(&dir.join("messages")).unwrap();
        let record = MessageRecord::new(&driver, "session", MessageAction::Message, "task".into());
        create_message(&dir, &record).unwrap();
        update_message(&dir, &record.id, |r| {
            r.result = Some("\u{0001}".repeat(MAX_RESULT_BYTES));
            r.error = Some("error".repeat(2 * 1024 * 1024));
            r.usage = Some(json!({"provider_extra": "x".repeat(1024 * 1024)}));
            r.transition(MessageState::Error);
        })
        .unwrap();
        let saved = load_message(&dir, &record.id).unwrap();
        assert_eq!(saved.state, MessageState::Error);
        assert!(saved.result_truncated);
        assert!(saved.error.unwrap().len() <= 128 * 1024);
        assert_eq!(saved.usage, Some(json!({"truncated": true})));
        assert!(fs::metadata(message_path(&dir, &record.id)).unwrap().len() <= MAX_RECORD_BYTES);
    }
}
