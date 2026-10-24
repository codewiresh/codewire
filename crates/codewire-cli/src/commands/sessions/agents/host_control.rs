//! Fixed target-owned record helper for authenticated member conversations,
//! and for the interrupt the host owner's own stop or restart sends first.
//!
//! This role never starts a provider or calls a daemon. The host daemon invokes
//! its own retained image, supplies its saved environment identity and writes
//! one bounded request to stdin. Network requests cannot select a program,
//! registry, provider endpoint or private helper operation.
use super::*;
use anyhow::ensure;
use std::ffi::OsString;

pub(super) const PROTOCOL: u32 = 1;
const MARKER: &str = "member-origin.json";
const GENERATION: &str = "member-generation.json";
// Match the daemon's bounded envelope for sixfold-escaped 64 KiB text.
const REQUEST_BYTES: usize = 512 * 1024;
const RESPONSE_BYTES: usize = 5 * 1024 * 1024;
const SUMMARY_BYTES: usize = 192 * 1024;

#[cfg(test)]
mod tests;

#[derive(Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Scope {
    environment_id: String,
    org_id: String,
    network_id: String,
    caller_key: [u8; 32],
    target_key: [u8; 32],
    grant_id: String,
    grant_revision: u64,
}
impl Scope {
    fn validate(&self, environment: &str) -> anyhow::Result<()> {
        ensure!(
            self.environment_id == environment,
            "member environment differs"
        );
        nonnil_id(&self.environment_id)?;
        nonnil_id(&self.grant_id)?;
        for value in [&self.org_id, &self.network_id] {
            ensure!(
                !value.is_empty()
                    && value.len() <= 256
                    && value.trim() == value
                    && !value.chars().any(char::is_control),
                "invalid member scope"
            );
        }
        ensure!(
            self.grant_revision > 0 && self.caller_key != [0; 32] && self.target_key != [0; 32],
            "invalid member scope"
        );
        Ok(())
    }
    fn same_principal(&self, other: &Self) -> bool {
        self.environment_id == other.environment_id
            && self.org_id == other.org_id
            && self.network_id == other.network_id
            && self.caller_key == other.caller_key
            && self.target_key == other.target_key
            && self.grant_id == other.grant_id
    }
}
#[derive(Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Origin {
    request_id: String,
    fingerprint: String,
    scope: Scope,
}
impl Origin {
    fn validate(&self, environment: &str) -> anyhow::Result<()> {
        nonnil_id(&self.request_id)?;
        ensure!(
            self.fingerprint.len() == 64
                && self
                    .fingerprint
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
            "invalid member fingerprint"
        );
        self.scope.validate(environment)
    }
}
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Marker {
    version: u32,
    origin: Origin,
    driver_id: String,
    session_id: String,
    parent_generation: Option<u64>,
}
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Generation {
    version: u32,
    driver_id: String,
    session_id: String,
    generation: u64,
}

#[derive(serde::Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
enum Request {
    Prepare {
        origin: Origin,
        agent: AgentKind,
        model: String,
        effort: Option<String>,
        working_dir: String,
        name: String,
        prompt: Option<String>,
        parent_session_id: String,
        expected_parent_launch_generation: u64,
    },
    Queue {
        origin: Origin,
        driver_id: String,
        session_id: String,
        action: MessageAction,
        text: String,
        reply_to: Option<String>,
        expected_turn_id: Option<String>,
        expected_active_message_id: Option<String>,
        launch_generation: u64,
    },
    MarkDelivery {
        scope: Scope,
        driver_id: String,
        session_id: String,
        message_id: String,
        outcome: native::DeliveryOutcome,
    },
    Read {
        scope: Scope,
        driver_id: String,
        session_id: String,
        message_id: String,
        limit: usize,
        launch_generation: u64,
    },
    AdvanceGeneration {
        origin: Origin,
        driver_id: String,
        session_id: String,
        expected_generation: u64,
    },
    PeerStatus {
        scope: Scope,
        driver_id: String,
        session_id: String,
    },
    Shutdown {
        scope: Scope,
        driver_id: String,
        session_id: String,
        operation_id: String,
        peer: guest_peer::PeerIdentity,
    },
    GetShutdown {
        scope: Scope,
        driver_id: String,
        session_id: String,
        operation_id: String,
        instance_id: String,
    },
    /// The host owner's own explicit stop or restart of a running
    /// conversation, named by its session's driver command and admitted by
    /// the conversation's binding to that session.
    InterruptBeforeStop {
        driver_id: String,
        session_id: String,
    },
    AwaitInterruptBeforeStop {
        driver_id: String,
        session_id: String,
        message_id: String,
    },
    /// The host daemon is stopping a running conversation because its whole
    /// environment is being taken down.
    PauseBeforeShutdown {
        driver_id: String,
        session_id: String,
    },
    /// Retention is about to remove a stopped conversation's session record.
    RetireBeforePrune {
        driver_id: String,
        session_id: String,
    },
    /// The host owner's explicit stop of a conversation that is not running.
    StopPaused {
        driver_id: String,
        session_id: String,
    },
}

/// How long the stop interrupt waits for an active run to report its ID,
/// which follows its start within milliseconds.
const STOP_INTERRUPT_RUN_WAIT: Duration = Duration::from_secs(1);
/// How long it waits for the interrupted message to end and its parent
/// notification to be written before the host daemon stops the session.
const STOP_INTERRUPT_SETTLE: Duration = Duration::from_secs(10);
const STOP_INTERRUPT_POLL: Duration = Duration::from_millis(25);

/// The bounds of an explicit stop's interrupt: how long it waits for the run
/// to report its ID, and for the interrupted message to settle.
#[derive(Clone, Copy, Debug)]
struct StopInterruptBounds {
    run_wait: Duration,
    settle: Duration,
}

impl StopInterruptBounds {
    const PRODUCT: Self = Self {
        run_wait: STOP_INTERRUPT_RUN_WAIT,
        settle: STOP_INTERRUPT_SETTLE,
    };
}

#[derive(clap::Parser)]
struct Arguments {
    #[arg(long)]
    environment: String,
    #[arg(long)]
    registry_root: PathBuf,
}

pub(crate) async fn run_from(arguments: Vec<OsString>) -> anyhow::Result<()> {
    // Full-chain formatting by an outer CLI must never expose request values.
    run(arguments).map_err(|_| anyhow::anyhow!("member managed record operation refused"))
}
fn run(arguments: Vec<OsString>) -> anyhow::Result<()> {
    let args = Arguments::try_parse_from(
        std::iter::once(OsString::from("__host-agent-control")).chain(arguments),
    )
    .map_err(|_| anyhow::anyhow!("invalid managed helper arguments"))?;
    nonnil_id(&args.environment)?;
    let root = args.registry_root.join(&args.environment);
    let _root = DirectoryPin::open(&root)?;
    let environment = host_environment_at(&root)?;
    ensure!(
        environment.id == args.environment,
        "member environment differs"
    );
    let environment = DriverEnvironment::Host(environment);
    let request = read_request(std::io::stdin().lock())?;
    let value = handle(&environment, request, &|agent| find_program(agent.name()))?;
    let mut bytes = serde_json::to_vec(&value)?;
    bytes.push(b'\n');
    ensure!(
        bytes.len() <= RESPONSE_BYTES,
        "managed record response too large"
    );
    _root.check()?;
    let mut output = std::io::stdout().lock();
    output.write_all(&bytes)?;
    output.flush()?;
    Ok(())
}

fn read_request(input: impl std::io::Read) -> anyhow::Result<Request> {
    let mut bytes = Vec::new();
    input
        .take(REQUEST_BYTES as u64 + 1)
        .read_to_end(&mut bytes)?;
    ensure!(bytes.len() <= REQUEST_BYTES, "managed request too large");
    serde_json::from_slice(&bytes).map_err(|_| anyhow::anyhow!("invalid managed record request"))
}

fn nonnil_id(value: &str) -> anyhow::Result<()> {
    canonical_uuid(value)?;
    ensure!(
        !uuid::Uuid::parse_str(value)?.is_nil(),
        "nil member identity"
    );
    Ok(())
}

/// The platform workspace home is the Pod's own volume root. Kubernetes
/// leaves it root owned and group- or world-writable (fsGroup setgid 2775,
/// local-path 0777), and the workspace user cannot change that.
pub(super) const PLATFORM_HOME: &str = "/home/codewire";

/// An ancestor of managed state: a real directory owned by root or this user
/// that another UID cannot write, root's sticky shared directory, or the exact
/// platform home, held as an anchor. Everything below the home stays private.
pub(super) fn admitted_ancestor(path: &Path, meta: &fs::Metadata, home: &Path) -> bool {
    meta.is_dir()
        && (meta.uid() == 0 || meta.uid() == euid())
        && (meta.mode() & 0o022 == 0
            || (meta.uid() == 0 && meta.mode() & 0o1000 != 0)
            || path == home)
}

// Hold each nofollow directory in the authority chain through synchronous
// helper work. Another UID cannot replace a writable ancestor; same-UID/root
// adversaries are outside this trusted-host boundary.
pub(super) struct DirectoryPin(Vec<(PathBuf, fs::File)>);
impl DirectoryPin {
    pub(super) fn open(path: &Path) -> anyhow::Result<Self> {
        ensure!(
            path.is_absolute()
                && path.components().all(|c| matches!(
                    c,
                    std::path::Component::RootDir | std::path::Component::Normal(_)
                )),
            "managed state path is not canonical"
        );
        let mut held = Vec::new();
        let mut current = PathBuf::from("/");
        for component in path.components().skip(1) {
            current.push(component.as_os_str());
            let file = fs::OpenOptions::new()
                .read(true)
                .custom_flags(
                    libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
                )
                .open(&current)?;
            let meta = file.metadata()?;
            ensure!(
                admitted_ancestor(&current, &meta, Path::new(PLATFORM_HOME)),
                "managed state ancestor is unsafe"
            );
            held.push((current.clone(), file));
        }
        let leaf = held
            .last()
            .context("managed root cannot be /")?
            .1
            .metadata()?;
        ensure!(
            leaf.uid() == euid() && leaf.mode() & 0o7777 == 0o700,
            "managed state is not owner private"
        );
        let pin = Self(held);
        pin.check()?;
        Ok(pin)
    }
    pub(super) fn check(&self) -> anyhow::Result<()> {
        for (path, file) in &self.0 {
            let a = file.metadata()?;
            let b = fs::symlink_metadata(path)?;
            ensure!(
                b.is_dir()
                    && a.dev() == b.dev()
                    && a.ino() == b.ino()
                    && a.uid() == b.uid()
                    && a.mode() == b.mode(),
                "managed state path changed"
            );
        }
        Ok(())
    }
}
/// Reads one complete owner-private managed record. A writer replaces a
/// record by renaming a complete sibling over it (`write_private`), so the
/// file a read opens is one complete version even when a rename replaces it
/// during the read. The read returns that version, the one the path named
/// when it was opened, and is never repeated: a writer that keeps replacing
/// the record cannot starve it (#3283). Every read makes every check, and
/// none returns a file that changed while it was read.
pub(super) fn private_record<T: serde::de::DeserializeOwned>(path: &Path) -> anyhow::Result<T> {
    let directory = DirectoryPin::open(path.parent().context("managed record parent")?)?;
    let bytes = read_record_once(path)?;
    directory.check()?;
    serde_json::from_slice(&bytes).map_err(|_| anyhow::anyhow!("invalid managed record"))
}
/// The points in a record read where a test replaces the record.
#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum RecordReadStage {
    /// The record is open and not yet checked.
    Opened,
    /// The record's bytes are read and not yet compared with its checks.
    Read,
}
#[cfg(test)]
type RecordReadHook = Box<dyn FnMut(RecordReadStage)>;
#[cfg(test)]
thread_local! {
    pub(super) static DURING_RECORD_READ: std::cell::RefCell<Option<RecordReadHook>> =
        const { std::cell::RefCell::new(None) };
}
#[cfg(test)]
fn during_record_read(stage: RecordReadStage) {
    DURING_RECORD_READ.with_borrow_mut(|hook| {
        if let Some(hook) = hook {
            hook(stage);
        }
    });
}
/// The bytes of the record `path` names when it is opened.
fn read_record_once(path: &Path) -> anyhow::Result<Vec<u8>> {
    let mut file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(path)?;
    #[cfg(test)]
    during_record_read(RecordReadStage::Opened);
    let a = file.metadata()?;
    // A rename over the open file unlinks it, which changes its link count
    // and change time but not what was written. A file with no link left is
    // still the version the path named when it was opened; a second link is
    // refused.
    ensure!(
        a.is_file()
            && a.uid() == euid()
            && a.nlink() <= 1
            && a.mode() & 0o7777 == 0o600
            && a.len() <= MAX_RECORD_BYTES,
        "managed record is unsafe"
    );
    type Written = (u64, u64, u32, u32, u64, i64, i64);
    fn written(m: &fs::Metadata) -> Written {
        (
            m.dev(),
            m.ino(),
            m.uid(),
            m.mode(),
            m.len(),
            m.mtime(),
            m.mtime_nsec(),
        )
    }
    let mut bytes = Vec::new();
    (&mut file)
        .take(MAX_RECORD_BYTES + 1)
        .read_to_end(&mut bytes)?;
    #[cfg(test)]
    during_record_read(RecordReadStage::Read);
    let held = file.metadata()?;
    ensure!(
        bytes.len() as u64 <= MAX_RECORD_BYTES && written(&a) == written(&held),
        "managed record changed"
    );
    Ok(bytes)
}
fn marker(environment: &DriverEnvironment, driver: &str) -> anyhow::Result<Option<Marker>> {
    nonnil_id(driver)?;
    let path = agents_root(environment).join(driver).join(MARKER);
    match fs::symlink_metadata(&path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e.into()),
        Ok(_) => {
            let value: Marker = private_record(&path)?;
            value.origin.validate(environment.id())?;
            ensure!(
                value.version == PROTOCOL
                    && value.driver_id == driver
                    && value.origin.request_id == driver
                    && value.session_id == format!("session-{driver}")
                    && value.parent_generation.is_none_or(|v| v > 0),
                "member origin differs"
            );
            Ok(Some(value))
        }
    }
}
pub(super) fn guardian_required(
    environment: &DriverEnvironment,
    driver: &str,
) -> anyhow::Result<bool> {
    Ok(environment.host().is_none() || marker(environment, driver)?.is_some())
}
pub(super) fn admit_member_guardian(
    root: &Path,
    environment: &str,
    driver: &str,
    session: &str,
) -> anyhow::Result<()> {
    let environment = DriverEnvironment::Guest {
        id: environment.into(),
        root: root.into(),
    };
    let origin = marker(&environment, driver)?.context("member guardian origin is missing")?;
    ensure!(
        origin.session_id == session,
        "member guardian session differs"
    );
    Ok(())
}
pub(super) fn admit_parent_notification(
    environment: &DriverEnvironment,
    child: &str,
    parent: &str,
) -> anyhow::Result<()> {
    if let Some(child) = marker(environment, child)? {
        let parent = marker(environment, parent)?.context("member parent origin is absent")?;
        ensure!(
            child.origin.scope.same_principal(&parent.origin.scope),
            "member parent scope differs"
        );
    }
    Ok(())
}
pub(super) fn generation(
    environment: &DriverEnvironment,
    driver: &str,
) -> anyhow::Result<Option<u64>> {
    if marker(environment, driver)?.is_none() {
        return Ok(None);
    }
    let value: Generation =
        private_record(&agents_root(environment).join(driver).join(GENERATION))?;
    ensure!(
        value.version == PROTOCOL
            && value.driver_id == driver
            && value.session_id == format!("session-{driver}")
            && value.generation > 0,
        "member generation differs"
    );
    Ok(Some(value.generation))
}
pub(super) fn parent_generation(
    environment: &DriverEnvironment,
    child: &str,
    parent: &str,
) -> anyhow::Result<Option<u64>> {
    let Some(child) = marker(environment, child)? else {
        return Ok(None);
    };
    admit_parent_notification(environment, &child.driver_id, parent)?;
    let expected = child
        .parent_generation
        .context("member parent generation missing")?;
    ensure!(
        generation(environment, parent)? == Some(expected),
        "member parent incarnation changed"
    );
    Ok(Some(expected))
}
fn admit(
    environment: &DriverEnvironment,
    scope: &Scope,
    driver: &str,
    session: &str,
) -> anyhow::Result<PathBuf> {
    scope.validate(environment.id())?;
    let marker = marker(environment, driver)?.context("member origin is missing")?;
    ensure!(
        marker.session_id == session && marker.origin.scope.same_principal(scope),
        "member origin differs"
    );
    let dir = driver_dir(environment, driver)?;
    let config: AgentConfig = private_record(&dir.join("config.json"))?;
    config.validate(environment.id(), driver)?;
    let binding: AgentBinding = private_record(&dir.join("binding.json"))?;
    ensure!(
        binding.driver_id == driver && binding.session_id == session,
        "member binding differs"
    );
    Ok(dir)
}
fn handle(
    environment: &DriverEnvironment,
    request: Request,
    resolve: &dyn Fn(AgentKind) -> anyhow::Result<PathBuf>,
) -> anyhow::Result<Value> {
    handle_within(environment, request, resolve, StopInterruptBounds::PRODUCT)
}

/// [`handle`] with `bounds` in place of the stop interrupt's product bounds.
/// A test whose subject is neither lengthens them into a hang guard, so a
/// stalled CI slot cannot spend them.
fn handle_within(
    environment: &DriverEnvironment,
    request: Request,
    resolve: &dyn Fn(AgentKind) -> anyhow::Result<PathBuf>,
    bounds: StopInterruptBounds,
) -> anyhow::Result<Value> {
    // A trusted host runs the user's own installed client.
    match request {
        Request::Prepare {
            origin,
            agent,
            model,
            effort,
            working_dir,
            name,
            prompt,
            parent_session_id,
            expected_parent_launch_generation,
        } => {
            origin.validate(environment.id())?;
            if let Some(prompt) = &prompt {
                validate_text(prompt)?;
            }
            let parent = if parent_session_id.is_empty() {
                ensure!(
                    expected_parent_launch_generation == 0,
                    "unexpected member parent generation"
                );
                None
            } else {
                let id = parent_session_id
                    .strip_prefix("session-")
                    .context("invalid parent session")?;
                admit(environment, &origin.scope, id, &parent_session_id)?;
                ensure!(
                    generation(environment, id)? == Some(expected_parent_launch_generation),
                    "member parent generation differs"
                );
                let driver_id = id.to_owned();
                Some(ParentLink {
                    session_id: parent_session_id,
                    driver_id,
                })
            };
            private_directory(&agents_root(environment))?;
            let _root = DirectoryPin::open(&agents_root(environment))?;
            let dir = agents_root(environment).join(&origin.request_id);
            // Never continue a half-prepared Issued launch after caller loss or
            // crash. Its target journal will recover Unknown, not invoke us again.
            ensure!(
                fs::symlink_metadata(&dir).is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound),
                "member driver is already reserved"
            );
            let driver_id = origin.request_id.clone();
            let session_id = format!("session-{driver_id}");
            let message_id = prompt.as_ref().map(|_| driver_id.clone());
            let parent_generation = parent.as_ref().map(|_| expected_parent_launch_generation);
            let config = AgentConfig {
                version: 1,
                driver_id: driver_id.clone(),
                environment_id: environment.id().into(),
                agent,
                program: PathBuf::new(),
                program_fallback: None,
                model,
                effort,
                working_dir,
                name,
                parent,
                initial_message_id: message_id.clone(),
                created_at: now(),
            };
            native::handle(
                environment,
                native::ControlRequest::Prepare { config },
                resolve,
            )?;
            let _pin = DirectoryPin::open(&dir)?;
            write_private_json(
                &dir.join(MARKER),
                &Marker {
                    version: PROTOCOL,
                    origin,
                    driver_id: driver_id.clone(),
                    session_id: session_id.clone(),
                    parent_generation,
                },
            )?;
            write_private_json(
                &dir.join(GENERATION),
                &Generation {
                    version: PROTOCOL,
                    driver_id: driver_id.clone(),
                    session_id: session_id.clone(),
                    generation: 1,
                },
            )?;
            native::handle(
                environment,
                native::ControlRequest::Bind {
                    driver_id: driver_id.clone(),
                    session_id,
                    prompt,
                },
                resolve,
            )?;
            if let Some(id) = &message_id {
                update_message(&dir, id, |r| r.member_launch_generation = Some(1))?;
            }
            _pin.check()?;
            _root.check()?;
            Ok(json!({"driver_id":driver_id,"message_id":message_id.unwrap_or_default()}))
        }
        Request::Queue {
            origin,
            driver_id,
            session_id,
            action,
            text,
            reply_to,
            expected_turn_id,
            expected_active_message_id,
            launch_generation,
        } => {
            origin.validate(environment.id())?;
            let dir = admit(environment, &origin.scope, &driver_id, &session_id)?;
            let _pin = DirectoryPin::open(&dir)?;
            let _control = StateLock::acquire(&dir.join("control.lock"))?;
            ensure!(
                generation(environment, &driver_id)? == Some(launch_generation),
                "member generation changed"
            );
            match action {
                MessageAction::Message | MessageAction::Steer => validate_text(&text)?,
                MessageAction::Interrupt if text.is_empty() => {}
                _ => anyhow::bail!("invalid member message action"),
            }
            if let Some(id) = &reply_to {
                nonnil_id(id)?;
            }
            if let Some(id) = &expected_active_message_id {
                nonnil_id(id)?;
            }
            if let Some(id) = &expected_turn_id {
                validate_token("turn", id)?;
            }
            if action == MessageAction::Message {
                ensure!(
                    expected_turn_id.is_none() && expected_active_message_id.is_none(),
                    "unexpected message turn"
                );
            } else {
                let state: DriverState = private_record(&dir.join("state.json"))?;
                ensure!(
                    state.driver_id == driver_id
                        && state.version == 1
                        && state.phase == DriverPhase::Busy
                        && state.active_message_id == expected_active_message_id
                        && expected_active_message_id.is_some()
                        && state.current_turn_id == expected_turn_id,
                    "active member turn changed"
                );
                ensure!(
                    if action == MessageAction::Steer {
                        state.capabilities.steer && expected_turn_id.is_some()
                    } else {
                        state.capabilities.interrupt && reply_to.is_none()
                    },
                    "member control unsupported"
                );
            }
            let mut record = MessageRecord::new(&driver_id, &session_id, action, text);
            record.id = origin.request_id;
            record.reply_to = reply_to;
            record.member_launch_generation = Some(launch_generation);
            record.expected_turn_id = expected_turn_id;
            record.expected_active_message_id = expected_active_message_id;
            ensure!(
                create_message(&dir, &record)?,
                "member message is already reserved"
            );
            _pin.check()?;
            Ok(json!({"message_id":record.id}))
        }
        Request::MarkDelivery {
            scope,
            driver_id,
            session_id,
            message_id,
            outcome,
        } => {
            admit(environment, &scope, &driver_id, &session_id)?;
            let value = native::handle(
                environment,
                native::ControlRequest::MarkDelivery {
                    driver_id,
                    session_id,
                    message_id,
                    outcome,
                    error: match outcome {
                        native::DeliveryOutcome::Written => None,
                        _ => Some("member pipe delivery uncertain".into()),
                    },
                },
                resolve,
            )?;
            Ok(json!({"state":value["record"]["state"]}))
        }
        Request::Read {
            scope,
            driver_id,
            session_id,
            message_id,
            limit,
            launch_generation,
        } => {
            let dir = admit(environment, &scope, &driver_id, &session_id)?;
            ensure!(
                generation(environment, &driver_id)? == Some(launch_generation),
                "member generation differs"
            );
            if !message_id.is_empty() {
                nonnil_id(&message_id)?;
                let record: MessageRecord = private_record(&message_path(&dir, &message_id))?;
                record.validate(&dir, &message_id)?;
                ensure!(
                    record.target_session_id == session_id,
                    "member message binding differs"
                );
                let original = record
                    .member_launch_generation
                    .context("member message has no birth proof")?;
                ensure!(
                    original > 0
                        && original <= launch_generation
                        && (original == launch_generation || record.state.is_terminal()),
                    "old active member message cannot cross incarnations"
                );
                return Ok(json!({"record":record}));
            }
            ensure!(limit <= INBOX_LIMIT, "member inbox limit exceeded");
            let limit = if limit == 0 { 20 } else { limit };
            let binding: AgentBinding = private_record(&dir.join("binding.json"))?;
            let state = match fs::symlink_metadata(dir.join("state.json")) {
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
                Err(error) => return Err(error.into()),
                Ok(_) => Some(private_record::<DriverState>(&dir.join("state.json"))?),
            };
            if let Some(state) = &state {
                ensure!(
                    state.driver_id == driver_id && state.version == 1,
                    "member driver differs"
                );
            }
            let mut ids = message_ids(&dir)?;
            // Read one bounded record at a time; retain only summaries.
            let mut summaries = Vec::new();
            for id in ids.drain(..) {
                let record: MessageRecord = private_record(&message_path(&dir, &id))?;
                record.validate(&dir, &id)?;
                ensure!(
                    record.target_session_id == session_id,
                    "member message differs"
                );
                summaries.push(
                    json!({"id":record.id,"action":record.action,"state":record.state,
                    "native_acknowledged":record.native_acknowledged,"turn_id":record.turn_id,
                    "expected_turn_id":record.expected_turn_id,"created_at":record.created_at,
                    "member_launch_generation":record.member_launch_generation,
                    "notification":record.notification,"source":record.source}),
                );
                summaries.sort_by(|a, b| {
                    a["created_at"]
                        .as_str()
                        .cmp(&b["created_at"].as_str())
                        .then_with(|| a["id"].as_str().cmp(&b["id"].as_str()))
                });
                if summaries.len() > limit {
                    summaries.remove(0);
                }
            }
            let value = json!({"driver_id":driver_id,"binding":binding,"driver":state,"messages":summaries});
            ensure!(
                serde_json::to_vec(&value)?.len() <= SUMMARY_BYTES,
                "member inbox exceeds bound"
            );
            Ok(value)
        }
        Request::AdvanceGeneration {
            origin,
            driver_id,
            session_id,
            expected_generation,
        } => {
            origin.validate(environment.id())?;
            let dir = admit(environment, &origin.scope, &driver_id, &session_id)?;
            let _pin = DirectoryPin::open(&dir)?;
            let _control = StateLock::acquire(&dir.join("control.lock"))?;
            let _driver = StateLock::try_acquire(&dir.join("driver.lock"))?
                .context("old member driver is still alive")?;
            ensure!(
                generation(environment, &driver_id)? == Some(expected_generation),
                "member generation CAS failed"
            );
            guest_peer::require_clean_previous(&dir, environment.id(), &driver_id, &session_id)?
                .context("member family cleanup is missing")?;
            let next = expected_generation
                .checked_add(1)
                .context("member generation exhausted")?;
            write_private_json(
                &dir.join(GENERATION),
                &Generation {
                    version: PROTOCOL,
                    driver_id,
                    session_id,
                    generation: next,
                },
            )?;
            _pin.check()?;
            Ok(json!({"launch_generation":next}))
        }
        Request::PeerStatus {
            scope,
            driver_id,
            session_id,
        } => {
            admit(environment, &scope, &driver_id, &session_id)?;
            native::handle(
                environment,
                native::ControlRequest::PeerStatus {
                    driver_id,
                    session_id,
                },
                resolve,
            )
        }
        Request::Shutdown {
            scope,
            driver_id,
            session_id,
            operation_id,
            peer,
        } => {
            admit(environment, &scope, &driver_id, &session_id)?;
            native::handle(
                environment,
                native::ControlRequest::Shutdown {
                    driver_id,
                    session_id,
                    operation_id,
                    peer,
                },
                resolve,
            )
        }
        Request::GetShutdown {
            scope,
            driver_id,
            session_id,
            operation_id,
            instance_id,
        } => {
            admit(environment, &scope, &driver_id, &session_id)?;
            native::handle(
                environment,
                native::ControlRequest::GetShutdown {
                    driver_id,
                    session_id,
                    operation_id,
                    instance_id,
                },
                resolve,
            )
        }
        Request::InterruptBeforeStop {
            driver_id,
            session_id,
        } => interrupt_before_stop(environment, &driver_id, &session_id, bounds.run_wait),
        Request::AwaitInterruptBeforeStop {
            driver_id,
            session_id,
            message_id,
        } => await_interrupt_before_stop(
            environment,
            &driver_id,
            &session_id,
            &message_id,
            bounds.settle,
        ),
        Request::PauseBeforeShutdown {
            driver_id,
            session_id,
        } => pause_before_shutdown(environment, &driver_id, &session_id),
        Request::RetireBeforePrune {
            driver_id,
            session_id,
        } => resolve_paused(environment, &driver_id, &session_id, pause::RETIRED),
        Request::StopPaused {
            driver_id,
            session_id,
        } => resolve_paused(environment, &driver_id, &session_id, pause::STOPPED),
    }
}

/// A conversation bound to the session the host daemon is stopping.
fn bound_conversation(
    environment: &DriverEnvironment,
    driver: &str,
    session: &str,
) -> anyhow::Result<(PathBuf, AgentConfig)> {
    nonnil_id(driver)?;
    let dir = driver_dir(environment, driver)?;
    let config: AgentConfig = private_record(&dir.join("config.json"))?;
    config.validate(environment.id(), driver)?;
    let binding: AgentBinding = private_record(&dir.join("binding.json"))?;
    ensure!(
        binding.driver_id == driver && binding.session_id == session,
        "managed binding differs"
    );
    Ok((dir, config))
}

fn current_state(
    dir: &Path,
    driver: &str,
    agent: AgentKind,
) -> anyhow::Result<Option<DriverState>> {
    let path = dir.join("state.json");
    match fs::symlink_metadata(&path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
        Ok(_) => {
            let state: DriverState = private_record(&path)?;
            ensure!(
                state.version == 1 && state.driver_id == driver && state.agent == agent,
                "managed driver differs"
            );
            Ok(Some(state))
        }
    }
}

/// Records the interrupt an explicit stop or restart sends first: the fenced
/// record `cw interrupt` makes, for the active message and its run. Only an
/// agent that takes one gets one; for any other this answers at once and
/// records nothing. The host daemon delivers it to the driver's input.
///
/// A run that has not reported its ID within the wait still gets the
/// record, without a run: the driver refuses it, but it shows the stop was
/// explicit, so the message is never paused and never resumed later. So does
/// a run whose noel is starting again after a crash.
fn interrupt_before_stop(
    environment: &DriverEnvironment,
    driver: &str,
    session: &str,
    run_wait: Duration,
) -> anyhow::Result<Value> {
    let (dir, config) = bound_conversation(environment, driver, session)?;
    let agent = config.agent;
    let nothing = || json!({"agent": agent, "interrupt": null});
    if !agent.interrupts_before_stop() {
        return Ok(nothing());
    }
    let deadline = Instant::now() + run_wait;
    let (active, run) = loop {
        let Some(state) = current_state(&dir, driver, agent)? else {
            return Ok(nothing());
        };
        let Some(active) = state.active_message_id.filter(|_| {
            matches!(state.phase, DriverPhase::Busy | DriverPhase::Starting)
                && state.capabilities.interrupt
        }) else {
            return Ok(nothing());
        };
        match state.current_turn_id {
            Some(run) => break (active, Some(run)),
            None if Instant::now() < deadline => std::thread::sleep(STOP_INTERRUPT_POLL),
            None => break (active, None),
        }
    };
    let mut record = MessageRecord::new(driver, session, MessageAction::Interrupt, String::new());
    record.id = stop_interrupt_id(&active);
    record.expected_active_message_id = Some(active.clone());
    record.expected_turn_id = run.clone();
    let deliver = if create_message(&dir, &record)? {
        true
    } else {
        // An earlier stop recorded it; deliver it again only if no driver
        // has seen it yet.
        let saved = load_message(&dir, &record.id)?;
        ensure!(
            saved.action == MessageAction::Interrupt
                && saved.target_session_id == session
                && saved.expected_active_message_id.as_deref() == Some(active.as_str()),
            "stop interrupt differs"
        );
        saved.state == MessageState::Requested
    };
    Ok(
        json!({"agent": agent, "interrupt": {"message_id": record.id,
        "active_message_id": active, "run_id": run, "deliver": deliver}}),
    )
}

/// Pauses the active run of a conversation whose whole environment the host
/// daemon is taking down, before the daemon signals it: the message is
/// paused and its parent's one notice queued. Only a run noel can resume is
/// paused, and never one an explicit stop recorded its interrupt for; any
/// other conversation answers at once and nothing is recorded.
fn pause_before_shutdown(
    environment: &DriverEnvironment,
    driver: &str,
    session: &str,
) -> anyhow::Result<Value> {
    let (dir, config) = bound_conversation(environment, driver, session)?;
    let agent = config.agent;
    let nothing = || json!({"agent": agent, "paused": null});
    let Some(state) = current_state(&dir, driver, agent)? else {
        return Ok(nothing());
    };
    let Some(active) = state
        .active_message_id
        .filter(|_| state.capabilities.resume)
    else {
        return Ok(nothing());
    };
    let binding: AgentBinding = private_record(&dir.join("binding.json"))?;
    let record = pause::pause_message(environment, &dir, &config, &binding, &active)?;
    if record.state != MessageState::Paused {
        return Ok(nothing());
    }
    Ok(json!({"agent": agent, "paused": active}))
}

/// A stopped conversation's paused messages will not resume: retention is
/// about to remove its session record, so it can never start again, or its
/// owner explicitly stopped it, so its next start must not continue the
/// run. Each paused message ends unknown, once, with `why`, and its parent
/// hears of it once. Other messages, and conversations with none paused,
/// are left as they are.
fn resolve_paused(
    environment: &DriverEnvironment,
    driver: &str,
    session: &str,
    why: &str,
) -> anyhow::Result<Value> {
    let (dir, config) = bound_conversation(environment, driver, session)?;
    if !pause::has_paused(&dir)? {
        return Ok(json!({"agent": config.agent, "resolved": []}));
    }
    let binding: AgentBinding = private_record(&dir.join("binding.json"))?;
    let resolved = pause::resolve_paused(environment, &dir, &config, &binding, why)?;
    Ok(json!({"agent": config.agent, "resolved": resolved}))
}

/// Waits at most 10 s for a stop interrupt's message to end and, for a
/// worker, for its parent notification to be written; it only reads. A
/// refused interrupt ends the wait at once, as nothing else will end the run.
fn await_interrupt_before_stop(
    environment: &DriverEnvironment,
    driver: &str,
    session: &str,
    message: &str,
    settle: Duration,
) -> anyhow::Result<Value> {
    let (dir, config) = bound_conversation(environment, driver, session)?;
    nonnil_id(message)?;
    let interrupt = load_message(&dir, message)?;
    let active = interrupt
        .expected_active_message_id
        .clone()
        .context("stop interrupt names no message")?;
    ensure!(
        interrupt.action == MessageAction::Interrupt
            && interrupt.target_session_id == session
            && interrupt.id == stop_interrupt_id(&active),
        "not a stop interrupt"
    );
    let deadline = Instant::now() + settle;
    loop {
        let interrupt = load_message(&dir, message)?;
        let run = load_message(&dir, &active)?;
        // The driver sets a notification pending, then records how its
        // delivery went; pending with a detail is where it rests.
        let notification = run
            .notification
            .as_ref()
            .filter(|n| n.state != NotificationState::Pending || n.detail.is_some())
            .map(|n| n.state);
        let settled =
            run.state.is_terminal() && (config.parent.is_none() || notification.is_some());
        let refused = interrupt.state.is_terminal() && !run.state.is_terminal();
        if settled || refused || Instant::now() >= deadline {
            return Ok(
                json!({"settled": settled, "message_state": run.state.name(),
                "interrupt_state": interrupt.state.name(), "notification_state": notification}),
            );
        }
        std::thread::sleep(STOP_INTERRUPT_POLL);
    }
}
