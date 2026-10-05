//! Fixed target-owned record helper for authenticated member conversations.
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
                meta.is_dir()
                    && (meta.uid() == 0 || meta.uid() == euid())
                    && (meta.mode() & 0o022 == 0 || (meta.uid() == 0 && meta.mode() & 0o1000 != 0)),
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
pub(super) fn private_record<T: serde::de::DeserializeOwned>(path: &Path) -> anyhow::Result<T> {
    let directory = DirectoryPin::open(path.parent().context("managed record parent")?)?;
    let mut file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(path)?;
    let a = file.metadata()?;
    ensure!(
        a.is_file()
            && a.uid() == euid()
            && a.nlink() == 1
            && a.mode() & 0o7777 == 0o600
            && a.len() <= MAX_RECORD_BYTES,
        "managed record is unsafe"
    );
    fn stamp(m: &fs::Metadata) -> (u64, u64, u32, u32, u64, u64, i64, i64, i64, i64) {
        (
            m.dev(),
            m.ino(),
            m.uid(),
            m.mode(),
            m.nlink(),
            m.len(),
            m.mtime(),
            m.mtime_nsec(),
            m.ctime(),
            m.ctime_nsec(),
        )
    }
    let mut bytes = Vec::new();
    (&mut file)
        .take(MAX_RECORD_BYTES + 1)
        .read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() as u64 <= MAX_RECORD_BYTES
            && stamp(&a) == stamp(&file.metadata()?)
            && stamp(&a) == stamp(&fs::symlink_metadata(path)?),
        "managed record changed"
    );
    directory.check()?;
    serde_json::from_slice(&bytes).map_err(|_| anyhow::anyhow!("invalid managed record"))
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
    }
}
