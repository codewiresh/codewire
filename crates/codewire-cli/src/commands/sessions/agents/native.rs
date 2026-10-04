//! Guest-side records for managed agent conversations in a Linux VM.
//!
//! The host runs the hidden `cw _agent-control` helper once per request over
//! its guest exec transport: one strict JSON request on stdin, one JSON
//! response on stdout, or a sanitized error and a nonzero exit. The helper
//! reads and writes only owner-private records under the admitted guest root,
//! with the same locks and monotonic transitions as host conversations. It
//! never launches a provider, writes session input, or calls a daemon or host
//! registry; the host owns launch, delivery and waiting.
use super::*;
use serde_json::{Value, json};
use std::path::{Component, Path};

// Sixfold JSON escaping of legal 64 KiB text plus its closed metadata.
const MAX_REQUEST_BYTES: usize = 512 * 1024;
// Preserve every admitted 4 MiB journal record, including response framing
// and a config/binding whose input is itself bounded to 512 KiB.
const MAX_RESPONSE_BYTES: usize = 5 * 1024 * 1024;
const RESPONSE_FRAMING_BYTES: usize = 4 * 1024;
const MAX_ERROR_BYTES: usize = 4 * 1024;
const MAX_WORKING_DIR_BYTES: usize = 4 * 1024;
/// Serializes guest preparation and binding. Taken before, never inside,
/// `messages.lock`.
const CONTROL_LOCK: &str = "control.lock";

#[derive(Debug, clap::Args)]
pub(crate) struct AgentControlArgs {
    #[arg(long, help = "Guest environment ID")]
    pub(crate) environment: String,
    #[arg(long, help = "Admitted owner-private guest state directory")]
    pub(crate) guest_root: PathBuf,
}

/// One host request. The host serializes this same closed type.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub(super) enum ControlRequest {
    Prepare {
        config: AgentConfig,
    },
    Bind {
        driver_id: String,
        session_id: String,
        prompt: Option<String>,
    },
    Queue {
        driver_id: String,
        session_id: String,
        message_id: String,
        action: MessageAction,
        text: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        reply_to: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        turn_id: Option<String>,
    },
    MarkDelivery {
        driver_id: String,
        session_id: String,
        message_id: String,
        outcome: DeliveryOutcome,
        error: Option<String>,
    },
    Status {
        driver_id: String,
        session_id: String,
        limit: usize,
    },
    GetMessage {
        driver_id: String,
        message_id: String,
    },
    Lookup {
        message_id: String,
    },
    Shutdown {
        driver_id: String,
        session_id: String,
        operation_id: String,
        peer: guest_peer::PeerIdentity,
    },
    GetShutdown {
        driver_id: String,
        session_id: String,
        operation_id: String,
        instance_id: String,
    },
    PeerStatus {
        driver_id: String,
        session_id: String,
    },
    /// A struct variant so unknown fields are refused here too.
    ProtocolInfo {},
}

/// The host's session input result for a queued record.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum DeliveryOutcome {
    /// The guest daemon acknowledged the control line.
    Written,
    /// Refused before any byte could reach the driver pipe.
    DefinitiveFailure,
    /// The line may have been written; it is never replayed.
    AmbiguousFailure,
}

pub(crate) async fn run_agent_control(args: AgentControlArgs) -> anyhow::Result<()> {
    // Diagnostics cross the guest boundary: one bounded line, no request values.
    agent_control(&args).map_err(|error| anyhow::anyhow!(sanitize_error(&format!("{error:#}"))))
}

fn agent_control(args: &AgentControlArgs) -> anyhow::Result<()> {
    let environment = guest_environment(args)?;
    let request = parse_request(&read_request(std::io::stdin().lock())?)?;
    let response = handle(&environment, request, &|agent| find_program(agent.name()))?;
    let response = encode_response(&response)?;
    let mut stdout = std::io::stdout().lock();
    stdout
        .write_all(&response)
        .context("write the agent control response")?;
    stdout.flush().context("flush the agent control response")
}

fn guest_environment(args: &AgentControlArgs) -> anyhow::Result<DriverEnvironment> {
    let id = canonical_uuid(&args.environment)?;
    let root = &args.guest_root;
    let normalized = root.is_absolute()
        && root.parent().is_some()
        && root
            .components()
            .all(|part| matches!(part, Component::RootDir | Component::Normal(_)))
        && root.components().collect::<PathBuf>().as_os_str() == root.as_os_str();
    if !normalized {
        anyhow::bail!("--guest-root must be a normalized absolute directory below /");
    }
    Ok(DriverEnvironment::Guest {
        id,
        root: root.clone(),
    })
}

fn read_request(input: impl std::io::Read) -> anyhow::Result<Vec<u8>> {
    let mut request = Vec::new();
    input
        .take(MAX_REQUEST_BYTES as u64 + 1)
        .read_to_end(&mut request)
        .context("read the agent control request")?;
    if request.len() > MAX_REQUEST_BYTES {
        anyhow::bail!("agent control request exceeds {MAX_REQUEST_BYTES} bytes");
    }
    Ok(request)
}

fn parse_request(request: &[u8]) -> anyhow::Result<ControlRequest> {
    serde_json::from_slice(request).map_err(|error| {
        use serde_json::error::Category;
        // serde messages can quote request values such as prompt text.
        let kind = match error.classify() {
            Category::Io => "unreadable input",
            Category::Syntax => "malformed JSON",
            Category::Data => "an unknown operation or invalid fields",
            Category::Eof => "truncated JSON",
        };
        anyhow::anyhow!(
            "invalid agent control request: {kind} at line {} column {}",
            error.line(),
            error.column()
        )
    })
}

fn encode_response(response: &Value) -> anyhow::Result<Vec<u8>> {
    let mut encoded = serde_json::to_vec(response)?;
    encoded.push(b'\n');
    if encoded.len() > MAX_RESPONSE_BYTES {
        anyhow::bail!("agent control response exceeds {MAX_RESPONSE_BYTES} bytes");
    }
    Ok(encoded)
}

fn sanitize_error(text: &str) -> String {
    let line: String = text
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect();
    match truncate_utf8(&line, MAX_ERROR_BYTES) {
        (line, true) => format!("{line}…"),
        (line, false) => line,
    }
}

type ResolveProgram<'a> = &'a dyn Fn(AgentKind) -> anyhow::Result<PathBuf>;

pub(super) fn handle(
    environment: &DriverEnvironment,
    request: ControlRequest,
    resolve: ResolveProgram<'_>,
) -> anyhow::Result<Value> {
    match request {
        ControlRequest::Prepare { config } => prepare(environment, config, resolve),
        ControlRequest::Bind {
            driver_id,
            session_id,
            prompt,
        } => bind(environment, &driver_id, &session_id, prompt),
        ControlRequest::Queue {
            driver_id,
            session_id,
            message_id,
            action,
            text,
            reply_to,
            turn_id,
        } => queue(
            environment,
            &driver_id,
            &session_id,
            QueueInput {
                message_id,
                action,
                text,
                reply_to,
                turn_id,
            },
        ),
        ControlRequest::MarkDelivery {
            driver_id,
            session_id,
            message_id,
            outcome,
            error,
        } => mark_delivery(
            environment,
            &driver_id,
            &session_id,
            &message_id,
            outcome,
            error.as_deref(),
        ),
        ControlRequest::Status {
            driver_id,
            session_id,
            limit,
        } => status(environment, &driver_id, &session_id, limit),
        ControlRequest::GetMessage {
            driver_id,
            message_id,
        } => get_message(environment, &driver_id, &message_id),
        ControlRequest::Lookup { message_id } => lookup(environment, &message_id),
        ControlRequest::Shutdown {
            driver_id,
            session_id,
            operation_id,
            peer,
        } => request_shutdown(environment, &driver_id, &session_id, &operation_id, &peer),
        ControlRequest::GetShutdown {
            driver_id,
            session_id,
            operation_id,
            instance_id,
        } => get_shutdown(
            environment,
            &driver_id,
            &session_id,
            &operation_id,
            &instance_id,
        ),
        ControlRequest::PeerStatus {
            driver_id,
            session_id,
        } => peer_status(environment, &driver_id, &session_id),
        ControlRequest::ProtocolInfo {} => {
            Ok(json!({"protocol_version": GUEST_AGENT_PROTOCOL_VERSION}))
        }
    }
}

// ---------------------------------------------------------------------------
// Identity and binding
// ---------------------------------------------------------------------------

fn canonical_session_id(value: &str) -> anyhow::Result<()> {
    match value.strip_prefix("session-").map(canonical_uuid) {
        Some(Ok(_)) => Ok(()),
        _ => anyhow::bail!("session ID must be a canonical session-<uuid> identifier"),
    }
}

/// A prepared guest conversation. Session-scoped callers prove its binding.
struct GuestDriver {
    id: String,
    dir: PathBuf,
    config: AgentConfig,
}

fn guest_driver(environment: &DriverEnvironment, driver_id: &str) -> anyhow::Result<GuestDriver> {
    let id = canonical_uuid(driver_id)?;
    let dir = driver_dir(environment, &id)?;
    let config: AgentConfig = read_record(&dir.join("config.json"))?;
    config.validate(environment.id(), &id)?;
    Ok(GuestDriver { id, dir, config })
}

fn saved_binding(driver: &GuestDriver) -> anyhow::Result<Option<AgentBinding>> {
    let binding = read_optional::<AgentBinding>(&driver.dir.join("binding.json"))?;
    if let Some(binding) = &binding
        && (binding.driver_id != driver.id || canonical_session_id(&binding.session_id).is_err())
    {
        anyhow::bail!(
            "managed conversation binding does not belong to driver {}",
            driver.id
        );
    }
    Ok(binding)
}

fn bound_driver(
    environment: &DriverEnvironment,
    driver_id: &str,
    session_id: &str,
) -> anyhow::Result<(GuestDriver, AgentBinding)> {
    canonical_session_id(session_id)?;
    let driver = guest_driver(environment, driver_id)?;
    let binding = saved_binding(&driver)?
        .context("managed conversation has no session binding; its launch did not complete")?;
    if binding.session_id != session_id {
        anyhow::bail!("managed conversation binding does not match session {session_id}");
    }
    Ok((driver, binding))
}

fn driver_state(driver: &GuestDriver) -> anyhow::Result<Option<DriverState>> {
    let state = read_optional::<DriverState>(&driver.dir.join("state.json"))?;
    if let Some(state) = &state
        && (state.version != 1
            || state.driver_id != driver.id
            || state.agent != driver.config.agent)
    {
        anyhow::bail!(
            "managed driver state does not belong to driver {}",
            driver.id
        );
    }
    Ok(state)
}

/// The operation remains durable when the requesting CLI or its input RPC is
/// cancelled. Only the driver owning this exact peer instance can accept it.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ShutdownRecord {
    pub(super) version: u32,
    pub(super) operation_id: String,
    pub(super) peer: guest_peer::PeerIdentity,
    pub(super) requested_at: String,
    pub(super) accepted_at: Option<String>,
    pub(super) finished_at: Option<String>,
    pub(super) cleanup_unknown: bool,
    pub(super) error: Option<String>,
}

fn shutdown_path(dir: &Path, instance_id: &str) -> anyhow::Result<PathBuf> {
    Ok(dir.join(format!("shutdown-{}.json", canonical_uuid(instance_id)?)))
}

fn validate_shutdown(
    record: &ShutdownRecord,
    peer: &guest_peer::PeerIdentity,
) -> anyhow::Result<()> {
    canonical_uuid(&record.operation_id)?;
    if record.version != 1 || record.peer != *peer {
        anyhow::bail!("managed shutdown does not match the current peer instance");
    }
    Ok(())
}

fn current_peer(
    environment: &DriverEnvironment,
    driver: &GuestDriver,
    session_id: &str,
) -> anyhow::Result<(DriverState, guest_peer::PeerReceipt)> {
    let state = driver_state(driver)?.context("guest driver has not established peer custody")?;
    let peer = guest_peer::current_receipt(&driver.dir, environment.id(), &driver.id, session_id)?
        .context("guest peer custody is missing; stop/restart is fenced")?;
    if state.started_at != peer.identity.driver_started_at {
        anyhow::bail!("guest peer custody belongs to another driver instance");
    }
    Ok((state, peer))
}

fn peer_status(
    environment: &DriverEnvironment,
    driver_id: &str,
    session_id: &str,
) -> anyhow::Result<Value> {
    let (driver, _) = bound_driver(environment, driver_id, session_id)?;
    let (state, peer) = current_peer(environment, &driver, session_id)?;
    let shutdown =
        read_optional::<ShutdownRecord>(&shutdown_path(&driver.dir, &peer.identity.instance_id)?)?;
    if let Some(record) = &shutdown {
        validate_shutdown(record, &peer.identity)?;
    }
    Ok(json!({"driver":state, "peer":peer, "shutdown":shutdown}))
}

fn request_shutdown(
    environment: &DriverEnvironment,
    driver_id: &str,
    session_id: &str,
    operation_id: &str,
    expected_peer: &guest_peer::PeerIdentity,
) -> anyhow::Result<Value> {
    let operation_id = canonical_uuid(operation_id)?;
    let (driver, _) = bound_driver(environment, driver_id, session_id)?;
    let _lock = StateLock::acquire(&driver.dir.join(CONTROL_LOCK))?;
    let (state, peer) = current_peer(environment, &driver, session_id)?;
    if peer.identity != *expected_peer {
        anyhow::bail!("guest peer changed before shutdown admission; no operation was created");
    }
    let path = shutdown_path(&driver.dir, &peer.identity.instance_id)?;
    let record = if let Some(saved) = read_optional::<ShutdownRecord>(&path)? {
        validate_shutdown(&saved, &peer.identity)?;
        if saved.operation_id != operation_id {
            anyhow::bail!("another shutdown operation already owns this peer instance");
        }
        saved
    } else {
        let already_stopped = state.phase == DriverPhase::Stopped
            && !peer.cleanup_unknown
            && peer.finished_at.is_some();
        let record = ShutdownRecord {
            version: 1,
            operation_id,
            peer: peer.identity.clone(),
            requested_at: now(),
            accepted_at: already_stopped.then(now),
            finished_at: already_stopped.then(now),
            cleanup_unknown: !already_stopped,
            error: None,
        };
        write_private_json(&path, &record)?;
        record
    };
    Ok(json!({"shutdown":record, "driver":state, "peer":peer}))
}

fn get_shutdown(
    environment: &DriverEnvironment,
    driver_id: &str,
    session_id: &str,
    operation_id: &str,
    instance_id: &str,
) -> anyhow::Result<Value> {
    canonical_uuid(operation_id)?;
    let (driver, _) = bound_driver(environment, driver_id, session_id)?;
    let (state, peer) = current_peer(environment, &driver, session_id)?;
    let record: ShutdownRecord = read_record(&shutdown_path(&driver.dir, instance_id)?)?;
    validate_shutdown(&record, &peer.identity)?;
    if record.operation_id != operation_id || peer.identity.instance_id != instance_id {
        anyhow::bail!("managed shutdown operation identity changed");
    }
    Ok(json!({"shutdown":record, "driver":state, "peer":peer}))
}

pub(super) fn admit_shutdown(
    dir: &Path,
    peer: &guest_peer::PeerIdentity,
) -> anyhow::Result<Option<ShutdownRecord>> {
    let _lock = StateLock::acquire(&dir.join(CONTROL_LOCK))?;
    let path = shutdown_path(dir, &peer.instance_id)?;
    let Some(mut record) = read_optional::<ShutdownRecord>(&path)? else {
        return Ok(None);
    };
    validate_shutdown(&record, peer)?;
    if record.finished_at.is_some() {
        return Ok(None);
    }
    if record.accepted_at.is_none() {
        record.accepted_at = Some(now());
        write_private_json(&path, &record)?;
    }
    Ok(Some(record))
}

pub(super) fn complete_shutdown(
    dir: &Path,
    request: &ShutdownRecord,
    error: Option<&str>,
) -> anyhow::Result<()> {
    let _lock = StateLock::acquire(&dir.join(CONTROL_LOCK))?;
    let path = shutdown_path(dir, &request.peer.instance_id)?;
    let mut record: ShutdownRecord = read_record(&path)?;
    validate_shutdown(&record, &request.peer)?;
    if record.operation_id != request.operation_id {
        anyhow::bail!("managed shutdown operation identity changed");
    }
    let receipt = guest_peer::read_receipt(dir, &record.peer)?;
    let state: DriverState = read_record(&dir.join("state.json"))?;
    let confirmed = error.is_none()
        && !receipt.cleanup_unknown
        && receipt.finished_at.is_some()
        && state.driver_id == record.peer.driver_id
        && state.started_at == record.peer.driver_started_at
        && state.phase == DriverPhase::Stopped;
    record.finished_at = Some(now());
    record.cleanup_unknown = !confirmed;
    record.error = if confirmed {
        None
    } else {
        Some(sanitize_error(error.unwrap_or(
            "guest peer cleanup is unknown; restart is fenced",
        )))
    };
    write_private_json(&path, &record)
}

fn saved_message(dir: &Path, id: &str) -> anyhow::Result<Option<MessageRecord>> {
    let Some(record) = read_optional::<MessageRecord>(&message_path(dir, id))? else {
        return Ok(None);
    };
    record.validate(dir, id)?;
    Ok(Some(record))
}

/// A caller-chosen ID may be reused only to repeat the identical request. An
/// implicit steer or interrupt target keeps the snapshot from the first call.
fn ensure_same_request(
    saved: &MessageRecord,
    requested: &MessageRecord,
    explicit_turn: Option<&str>,
) -> anyhow::Result<()> {
    if saved.driver_id != requested.driver_id
        || saved.target_session_id != requested.target_session_id
        || saved.action != requested.action
        || saved.text != requested.text
        || saved.reply_to != requested.reply_to
        || explicit_turn.is_some_and(|turn| saved.expected_turn_id.as_deref() != Some(turn))
    {
        anyhow::bail!(
            "message ID {} already exists with a different request",
            saved.id
        );
    }
    Ok(())
}

/// Creates a caller-identified record once; a retry returns the saved record
/// and whatever state it has settled in.
fn create_or_reuse(
    dir: &Path,
    record: MessageRecord,
    explicit_turn: Option<&str>,
) -> anyhow::Result<MessageRecord> {
    if create_message(dir, &record)? {
        return Ok(record);
    }
    let saved = load_message(dir, &record.id)?;
    ensure_same_request(&saved, &record, explicit_turn)?;
    Ok(saved)
}

// ---------------------------------------------------------------------------
// Operations
// ---------------------------------------------------------------------------

fn validate_launch(config: &AgentConfig) -> anyhow::Result<()> {
    if !config.program.as_os_str().is_empty() {
        anyhow::bail!(
            "the agent program is resolved inside the guest; prepare with an empty program"
        );
    }
    validate_token("model", &config.model)?;
    if agent_effort(config.agent, config.effort.as_deref())? != config.effort {
        anyhow::bail!(
            "{} effort must be the explicit effort the launch resolved",
            config.agent.name()
        );
    }
    if !Path::new(&config.working_dir).is_absolute()
        || config.working_dir.len() > MAX_WORKING_DIR_BYTES
        || config.working_dir.contains('\0')
    {
        anyhow::bail!("the working directory must be an absolute guest path");
    }
    if !config.name.is_empty() && !codewire_gateway_proto::valid_session_name(&config.name) {
        anyhow::bail!("the conversation name must be a valid session name");
    }
    if let Some(id) = &config.initial_message_id {
        canonical_uuid(id)?;
    }
    chrono::DateTime::parse_from_rfc3339(&config.created_at)
        .context("created_at must be an RFC 3339 timestamp")?;
    if let Some(parent) = &config.parent {
        canonical_uuid(&parent.driver_id)?;
        canonical_session_id(&parent.session_id)?;
        if parent.driver_id == config.driver_id {
            anyhow::bail!("a managed conversation cannot be its own parent");
        }
    }
    Ok(())
}

/// Launch identity without the guest-resolved program and timestamp.
fn launch_identity(config: &AgentConfig) -> anyhow::Result<Value> {
    let mut identity = serde_json::to_value(config)?;
    identity["program"] = Value::Null;
    identity["created_at"] = Value::Null;
    Ok(identity)
}

fn prepare(
    environment: &DriverEnvironment,
    mut config: AgentConfig,
    resolve: ResolveProgram<'_>,
) -> anyhow::Result<Value> {
    let driver_id = canonical_uuid(&config.driver_id)?;
    config.validate(environment.id(), &driver_id)?;
    validate_launch(&config)?;
    private_directory(&environment.root())?;
    let agents = agents_root(environment);
    private_directory(&agents)?;
    if let Some(parent) = &config.parent {
        bound_driver(environment, &parent.driver_id, &parent.session_id).map_err(|error| {
            anyhow::anyhow!(
                "parent {} has no semantic receiver for worker results in this guest: {error:#}",
                parent.session_id
            )
        })?;
    }
    let dir = agents.join(&driver_id);
    let fresh = match fs::symlink_metadata(&dir) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => true,
        Err(error) => return Err(error.into()),
        Ok(_) => false,
    };
    // Resolve first so a missing CLI leaves no half-prepared conversation.
    let program = if fresh {
        Some(resolve(config.agent)?)
    } else {
        None
    };
    private_directory(&dir)?;
    private_directory(&dir.join("messages"))?;
    let _lock = StateLock::acquire(&dir.join(CONTROL_LOCK))?;
    let path = dir.join("config.json");
    let config = match read_optional::<AgentConfig>(&path)? {
        Some(saved) => {
            saved.validate(environment.id(), &driver_id)?;
            if launch_identity(&saved)? != launch_identity(&config)? {
                anyhow::bail!(
                    "managed conversation {driver_id} was already prepared with a different configuration"
                );
            }
            saved
        }
        None => {
            config.program = match program {
                Some(program) => program,
                None => resolve(config.agent)?,
            };
            write_private_json(&path, &config)?;
            config
        }
    };
    Ok(json!({"config": config}))
}

fn bind(
    environment: &DriverEnvironment,
    driver_id: &str,
    session_id: &str,
    prompt: Option<String>,
) -> anyhow::Result<Value> {
    canonical_session_id(session_id)?;
    let driver = guest_driver(environment, driver_id)?;
    let initial = match (driver.config.initial_message_id.clone(), prompt) {
        (Some(id), Some(text)) => {
            validate_text(&text)?;
            let mut record =
                MessageRecord::new(&driver.id, session_id, MessageAction::Prompt, text);
            record.id = id;
            Some(record)
        }
        (None, None) => None,
        (Some(_), None) => anyhow::bail!("the prepared conversation expects its initial prompt"),
        (None, Some(_)) => {
            anyhow::bail!("the prepared conversation has no initial message ID for a prompt")
        }
    };
    let _lock = StateLock::acquire(&driver.dir.join(CONTROL_LOCK))?;
    let saved = saved_binding(&driver)?;
    if let Some(binding) = &saved
        && binding.session_id != session_id
    {
        anyhow::bail!(
            "managed conversation {} is already bound to session {}",
            driver.id,
            binding.session_id
        );
    }
    // The initial message exists before the binding the driver waits for.
    let message = match initial {
        None => None,
        Some(record) => {
            if saved.is_some() && saved_message(&driver.dir, &record.id)?.is_none() {
                anyhow::bail!(
                    "initial message {} is missing from a bound conversation; it is not recreated",
                    record.id
                );
            }
            Some(create_or_reuse(&driver.dir, record, None)?)
        }
    };
    let binding = match saved {
        Some(binding) => binding,
        None => {
            let binding = AgentBinding {
                driver_id: driver.id.clone(),
                session_id: session_id.into(),
                bound_at: now(),
            };
            write_private_json(&driver.dir.join("binding.json"), &binding)?;
            binding
        }
    };
    Ok(json!({"binding": binding, "message": message}))
}

/// One caller-identified message for a bound conversation.
struct QueueInput {
    message_id: String,
    action: MessageAction,
    text: String,
    reply_to: Option<String>,
    turn_id: Option<String>,
}

fn queue(
    environment: &DriverEnvironment,
    driver_id: &str,
    session_id: &str,
    input: QueueInput,
) -> anyhow::Result<Value> {
    let (driver, _) = bound_driver(environment, driver_id, session_id)?;
    let QueueInput {
        message_id,
        action,
        text,
        reply_to,
        turn_id,
    } = input;
    let message_id = canonical_uuid(&message_id)?;
    match action {
        MessageAction::Message | MessageAction::Steer => validate_text(&text)?,
        MessageAction::Interrupt if text.is_empty() => {}
        MessageAction::Interrupt => anyhow::bail!("an interrupt carries no message text"),
        MessageAction::Prompt | MessageAction::Notification => anyhow::bail!(
            "{} records are created by launch and workers; queue a message, steer or interrupt",
            action.name()
        ),
    }
    // The flag rules of `cw msg`, `cw steer` and `cw interrupt`.
    let reply_to = reply_to.as_deref().map(canonical_uuid).transpose()?;
    if action == MessageAction::Interrupt && reply_to.is_some() {
        anyhow::bail!("--reply-to applies only to `cw msg` and `cw steer`");
    }
    if action != MessageAction::Steer && turn_id.is_some() {
        anyhow::bail!("--turn-id applies only to `cw steer`");
    }
    if let Some(turn) = &turn_id {
        validate_token("turn ID", turn)?;
    }
    let mut record = MessageRecord::new(&driver.id, session_id, action, text);
    record.id = message_id;
    record.reply_to = reply_to;
    record.expected_turn_id = turn_id.clone();
    if let Some(saved) = saved_message(&driver.dir, &record.id)? {
        ensure_same_request(&saved, &record, turn_id.as_deref())?;
        return Ok(json!({"record": saved}));
    }
    if action != MessageAction::Message {
        let state = driver_state(&driver)?
            .context("the managed driver has not reported its capabilities yet")?;
        let agent = driver.config.agent.name();
        if action == MessageAction::Steer {
            if !state.capabilities.steer {
                anyhow::bail!(
                    "{agent} conversations do not support steering: {}",
                    state.capabilities.note
                );
            }
            if record.expected_turn_id.is_none() {
                record.expected_turn_id = Some(
                    state
                        .current_turn_id
                        .clone()
                        .context("no active turn to steer; use `cw msg` to queue a message")?,
                );
            }
        } else {
            if !state.capabilities.interrupt {
                anyhow::bail!(
                    "{agent} conversations do not support interrupt: {}",
                    state.capabilities.note
                );
            }
            record.expected_active_message_id = Some(
                state
                    .active_message_id
                    .clone()
                    .context("no active turn to interrupt")?,
            );
            record.expected_turn_id = state.current_turn_id.clone();
        }
    }
    let record = create_or_reuse(&driver.dir, record, turn_id.as_deref())?;
    Ok(json!({"record": record}))
}

fn mark_delivery(
    environment: &DriverEnvironment,
    driver_id: &str,
    session_id: &str,
    message_id: &str,
    outcome: DeliveryOutcome,
    error: Option<&str>,
) -> anyhow::Result<Value> {
    let (driver, _) = bound_driver(environment, driver_id, session_id)?;
    let message_id = canonical_uuid(message_id)?;
    let error = match (outcome, error) {
        (DeliveryOutcome::Written, None) => String::new(),
        (DeliveryOutcome::Written, Some(_)) => {
            anyhow::bail!("a written delivery carries no error")
        }
        (_, Some(error)) if !error.trim().is_empty() => sanitize_error(error),
        _ => anyhow::bail!("a delivery failure must state its error"),
    };
    let saved = load_message(&driver.dir, &message_id)?;
    if saved.target_session_id != session_id {
        anyhow::bail!("message {message_id} targets a different session binding");
    }
    if !matches!(
        saved.action,
        MessageAction::Message | MessageAction::Steer | MessageAction::Interrupt
    ) {
        anyhow::bail!(
            "{} records are not delivered through session input",
            saved.action.name()
        );
    }
    let record = update_message(&driver.dir, &message_id, |r| match outcome {
        DeliveryOutcome::Written => {
            r.transition(MessageState::PipeWritten);
        }
        // A recorded pipe write is never downgraded by a later report.
        _ if r.state == MessageState::PipeWritten => {}
        // Receiver acceptance and completion win over a lost pipe ACK.
        DeliveryOutcome::DefinitiveFailure => apply_delivery_failure(r, true, &error),
        DeliveryOutcome::AmbiguousFailure => apply_delivery_failure(r, false, &error),
    })?;
    Ok(json!({"record": record}))
}

/// Holds one record at a time while ordering, then reloads the newest.
fn newest_messages(dir: &Path, limit: usize) -> anyhow::Result<(usize, Vec<MessageRecord>)> {
    let mut order = Vec::new();
    for id in message_ids(dir)? {
        let record = load_message(dir, &id)?;
        order.push((record.created_at, record.id));
    }
    let total = order.len();
    order.sort();
    let newest = order
        .split_off(total.saturating_sub(limit))
        .into_iter()
        .map(|(_, id)| load_message(dir, &id))
        .collect::<anyhow::Result<Vec<_>>>()?;
    Ok((total, newest))
}

fn status(
    environment: &DriverEnvironment,
    driver_id: &str,
    session_id: &str,
    limit: usize,
) -> anyhow::Result<Value> {
    if limit > INBOX_LIMIT {
        anyhow::bail!("status returns at most {INBOX_LIMIT} messages");
    }
    let (driver, binding) = bound_driver(environment, driver_id, session_id)?;
    let state = driver_state(&driver)?;
    let (peer, peer_error) =
        match guest_peer::current_receipt(&driver.dir, environment.id(), &driver.id, session_id) {
            Ok(Some(peer))
                if state
                    .as_ref()
                    .is_some_and(|state| state.started_at != peer.identity.driver_started_at) =>
            {
                (
                    None,
                    Some("guest peer custody belongs to another driver instance".to_owned()),
                )
            }
            Ok(peer) => (peer, None),
            Err(error) => (None, Some(sanitize_error(&format!("{error:#}")))),
        };
    let (total, records) = newest_messages(&driver.dir, limit)?;
    let shutdown = match &peer {
        Some(peer) => {
            let record = read_optional::<ShutdownRecord>(&shutdown_path(
                &driver.dir,
                &peer.identity.instance_id,
            )?)?;
            if let Some(record) = &record {
                validate_shutdown(record, &peer.identity)?;
            }
            record
        }
        None => None,
    };
    let mut response = json!({
        "config": driver.config,
        "binding": binding,
        "driver": state,
        "peer": peer,
        "peer_error": peer_error,
        "shutdown": shutdown,
        "total_messages": total,
    });
    // Keep the newest contiguous messages that fit the response bound.
    let mut budget = MAX_RESPONSE_BYTES
        .saturating_sub(serde_json::to_vec(&response)?.len() + RESPONSE_FRAMING_BYTES);
    let mut messages = Vec::new();
    for record in records.into_iter().rev() {
        let size = serde_json::to_vec(&record)?.len() + 1;
        if size > budget {
            break;
        }
        budget -= size;
        messages.push(record);
    }
    messages.reverse();
    response["messages"] = json!(messages);
    Ok(response)
}

fn get_message(
    environment: &DriverEnvironment,
    driver_id: &str,
    message_id: &str,
) -> anyhow::Result<Value> {
    let driver = guest_driver(environment, driver_id)?;
    // A binding that no longer belongs to this driver fails closed.
    saved_binding(&driver)?;
    let record = load_message(&driver.dir, message_id)?;
    Ok(json!({"record": record}))
}

fn lookup(environment: &DriverEnvironment, message_id: &str) -> anyhow::Result<Value> {
    let message_id = canonical_uuid(message_id)?;
    existing_private_dir(&environment.root())?;
    let root = agents_root(environment);
    match fs::symlink_metadata(&root) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Value::Null),
        Err(error) => return Err(error.into()),
        Ok(_) => existing_private_dir(&root)?,
    }
    let mut found: Option<String> = None;
    for (count, entry) in fs::read_dir(&root)?.enumerate() {
        if count >= MAX_DRIVERS_SCANNED {
            anyhow::bail!(
                "guest environment has more than {MAX_DRIVERS_SCANNED} managed conversations"
            );
        }
        let entry = entry?;
        if !entry.file_type()?.is_dir() {
            continue;
        }
        let name = entry.file_name();
        let Some(driver_id) = name.to_str() else {
            continue;
        };
        if canonical_uuid(driver_id).is_err()
            || fs::symlink_metadata(message_path(&entry.path(), &message_id)).is_err()
        {
            continue;
        }
        if found.is_some() {
            anyhow::bail!(
                "message {message_id} exists in more than one managed conversation; refusing an ambiguous lookup"
            );
        }
        found = Some(driver_id.to_owned());
    }
    let Some(driver_id) = found else {
        return Ok(Value::Null);
    };
    let driver = guest_driver(environment, &driver_id)?;
    let binding = saved_binding(&driver)?;
    let record = load_message(&driver.dir, &message_id)?;
    Ok(json!({
        "config": driver.config,
        "binding": binding,
        "record": record,
        "driver_id": driver.id,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    const SESSION: &str = "session-0b8f4a54-7c43-4b0f-9b6e-0b3c2a1d9e01";
    const OTHER_SESSION: &str = "session-5d2c7e10-3f4a-4c1b-8e9d-6a7b8c9d0e1f";

    struct Guest {
        _temporary: tempfile::TempDir,
        environment: DriverEnvironment,
    }

    fn guest() -> Guest {
        let temporary = tempfile::tempdir().unwrap();
        let environment = guest_environment(&AgentControlArgs {
            environment: uuid::Uuid::new_v4().to_string(),
            guest_root: temporary.path().join("guest"),
        })
        .unwrap();
        Guest {
            _temporary: temporary,
            environment,
        }
    }

    fn launch(environment: &DriverEnvironment, agent: AgentKind, prompt: bool) -> AgentConfig {
        AgentConfig {
            version: 1,
            driver_id: uuid::Uuid::new_v4().to_string(),
            environment_id: environment.id().into(),
            agent,
            program: PathBuf::new(),
            model: agent.default_model().into(),
            effort: agent_effort(agent, None).unwrap(),
            working_dir: "/workspace".into(),
            name: "worker".into(),
            parent: None,
            initial_message_id: prompt.then(|| uuid::Uuid::new_v4().to_string()),
            created_at: now(),
        }
    }

    fn resolve_in_guest(agent: AgentKind) -> anyhow::Result<PathBuf> {
        Ok(PathBuf::from(format!("/guest/bin/{}", agent.name())))
    }

    /// Requests cross the same JSON boundary the host uses.
    fn run(environment: &DriverEnvironment, request: Value) -> anyhow::Result<Value> {
        let request = parse_request(&serde_json::to_vec(&request).unwrap())?;
        handle(environment, request, &resolve_in_guest)
    }

    fn prepare_request(config: &AgentConfig) -> Value {
        json!({"op": "prepare", "config": config})
    }

    /// A prepared conversation bound to `session` without an initial prompt.
    fn bound(environment: &DriverEnvironment, session: &str) -> (AgentConfig, PathBuf) {
        let config = launch(environment, AgentKind::Codex, false);
        run(environment, prepare_request(&config)).unwrap();
        let bound = run(
            environment,
            json!({"op": "bind", "driver_id": config.driver_id, "session_id": session}),
        )
        .unwrap();
        assert_eq!(bound["message"], Value::Null);
        let dir = agents_root(environment).join(&config.driver_id);
        (config, dir)
    }

    fn queue_request(driver: &str, session: &str, id: &str, action: &str, text: &str) -> Value {
        json!({
            "op": "queue",
            "driver_id": driver,
            "session_id": session,
            "message_id": id,
            "action": action,
            "text": text,
        })
    }

    fn mark_request(driver: &str, id: &str, outcome: &str, error: Option<&str>) -> Value {
        json!({
            "op": "mark_delivery",
            "driver_id": driver,
            "session_id": SESSION,
            "message_id": id,
            "outcome": outcome,
            "error": error,
        })
    }

    /// Records cross back into the host's closed record type.
    fn record(response: &Value) -> MessageRecord {
        serde_json::from_value(response["record"].clone()).unwrap()
    }

    fn keys(response: &Value) -> Vec<&str> {
        let mut keys: Vec<&str> = response
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        keys.sort_unstable();
        keys
    }

    fn write_state(
        dir: &Path,
        config: &AgentConfig,
        capable: bool,
        turn: Option<&str>,
        active: Option<&str>,
    ) {
        let at = now();
        write_private_json(
            &dir.join("state.json"),
            &DriverState {
                version: 1,
                driver_id: config.driver_id.clone(),
                agent: config.agent,
                phase: if active.is_some() {
                    DriverPhase::Busy
                } else {
                    DriverPhase::Idle
                },
                native_thread_id: Some("thread".into()),
                native_thread_established: true,
                current_turn_id: turn.map(str::to_owned),
                active_message_id: active.map(str::to_owned),
                queued: 0,
                capabilities: AgentCapabilities {
                    steer: capable,
                    interrupt: capable,
                    note: "reported by the test driver".into(),
                },
                policy: CODEX_POLICY.into(),
                last_error: None,
                started_at: at.clone(),
                updated_at: at,
            },
        )
        .unwrap();
    }

    fn mode(path: &Path) -> u32 {
        fs::symlink_metadata(path).unwrap().permissions().mode() & 0o777
    }

    fn new_id() -> String {
        uuid::Uuid::new_v4().to_string()
    }

    #[test]
    fn shutdown_is_durable_without_input_and_bound_to_one_peer_instance() {
        let guest = guest();
        let environment = &guest.environment;
        let (config, dir) = bound(environment, SESSION);
        write_state(&dir, &config, true, None, None);
        let state: DriverState = read_record(&dir.join("state.json")).unwrap();
        let peer = guest_peer::prepare(
            &dir,
            environment.id(),
            &config.driver_id,
            SESSION,
            &state.started_at,
        )
        .unwrap();
        let operation = new_id();
        let mut stale_peer = peer.clone();
        stale_peer.instance_id = new_id();
        assert!(
            run(
                environment,
                json!({"op":"shutdown", "driver_id":config.driver_id,
            "session_id":SESSION, "operation_id":operation, "peer":stale_peer})
            )
            .is_err()
        );
        assert!(!fs::read_dir(&dir).unwrap().any(|entry| {
            entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with("shutdown-")
        }));
        let request = json!({"op":"shutdown", "driver_id":config.driver_id,
            "session_id":SESSION, "operation_id":operation, "peer":peer});
        let created = run(environment, request.clone()).unwrap();
        assert_eq!(created["shutdown"]["operation_id"], operation);
        assert_eq!(created["shutdown"]["accepted_at"], Value::Null);
        assert_eq!(created["shutdown"]["cleanup_unknown"], true);
        assert_eq!(run(environment, request).unwrap(), created);
        assert!(
            run(
                environment,
                json!({"op":"shutdown", "driver_id":config.driver_id,
            "session_id":OTHER_SESSION, "operation_id":operation, "peer":peer})
            )
            .is_err()
        );
        assert!(
            run(
                environment,
                json!({"op":"shutdown", "driver_id":config.driver_id,
            "session_id":SESSION, "operation_id":new_id(), "peer":peer})
            )
            .is_err()
        );

        // No stdin hint or live provider is involved: the driver's periodic
        // adoption can accept the journal even after its CLI caller vanished.
        let admitted = admit_shutdown(&dir, &peer).unwrap().unwrap();
        assert!(admitted.accepted_at.is_some());
        assert_eq!(
            admit_shutdown(&dir, &peer).unwrap().unwrap().accepted_at,
            admitted.accepted_at
        );
        let mut wrong_birth = peer.clone();
        wrong_birth.driver_started_at = "2026-01-01T00:00:00Z".into();
        assert!(admit_shutdown(&dir, &wrong_birth).is_err());
        let mut next_instance = peer.clone();
        next_instance.instance_id = new_id();
        assert!(admit_shutdown(&dir, &next_instance).unwrap().is_none());
        assert!(run(environment, json!({"op":"get_shutdown", "driver_id":config.driver_id,
            "session_id":SESSION, "operation_id":operation, "instance_id":next_instance.instance_id})).is_err());

        // Neither an admitted request nor a stopped driver phase proves the
        // child family is gone while its guardian receipt is still unknown.
        let mut stopped = state;
        stopped.phase = DriverPhase::Stopped;
        write_private_json(&dir.join("state.json"), &stopped).unwrap();
        complete_shutdown(&dir, &admitted, None).unwrap();
        let result = run(
            environment,
            json!({"op":"get_shutdown", "driver_id":config.driver_id,
            "session_id":SESSION, "operation_id":operation, "instance_id":peer.instance_id}),
        )
        .unwrap();
        assert_eq!(result["shutdown"]["cleanup_unknown"], true);
        assert!(result["shutdown"]["error"].is_string());
        assert!(admit_shutdown(&dir, &peer).unwrap().is_none());
    }

    #[test]
    fn shutdown_without_peer_custody_refuses_before_creating_an_operation() {
        let guest = guest();
        let (config, dir) = bound(&guest.environment, SESSION);
        write_state(&dir, &config, true, None, None);
        let state: DriverState = read_record(&dir.join("state.json")).unwrap();
        let peer = guest_peer::PeerIdentity {
            environment_id: guest.environment.id().into(),
            driver_id: config.driver_id.clone(),
            session_id: SESSION.into(),
            instance_id: new_id(),
            driver_started_at: state.started_at,
            boot_id: new_id(),
            driver_pid: std::process::id(),
            driver_start_ticks: 1,
        };
        assert!(
            run(
                &guest.environment,
                json!({"op":"shutdown", "driver_id":config.driver_id,
            "session_id":SESSION, "operation_id":new_id(), "peer":peer})
            )
            .is_err()
        );
        assert!(!fs::read_dir(&dir).unwrap().any(|entry| {
            entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with("shutdown-")
        }));
        let history = run(
            &guest.environment,
            json!({"op":"status", "driver_id":config.driver_id,
            "session_id":SESSION, "limit":10}),
        )
        .unwrap();
        assert_eq!(history["messages"], json!([]));
        assert_eq!(history["peer"], Value::Null);
    }

    #[test]
    fn guest_intake_preserves_escaped_text_and_refuses_excess_or_trailing_data() {
        let guest = guest();
        let environment = &guest.environment;
        let intake = |bytes: &[u8]| -> anyhow::Result<Value> {
            let request = parse_request(&read_request(bytes)?)?;
            handle(environment, request, &resolve_in_guest)
        };
        let config = launch(environment, AgentKind::Codex, true);
        let prepared = serde_json::to_vec(&ControlRequest::Prepare {
            config: config.clone(),
        })
        .unwrap();
        intake(&prepared).unwrap();
        let text = "\u{1}".repeat(MAX_TEXT_BYTES);
        let bind = ControlRequest::Bind {
            driver_id: config.driver_id.clone(),
            session_id: SESSION.into(),
            prompt: Some(text.clone()),
        };
        let encoded = serde_json::to_vec(&bind).unwrap();
        assert!(encoded.len() > 256 * 1024);
        let bound = intake(&encoded).unwrap();
        assert_eq!(bound["message"]["text"], text);
        let queue = |text: &str| ControlRequest::Queue {
            driver_id: config.driver_id.clone(),
            session_id: SESSION.into(),
            message_id: new_id(),
            action: MessageAction::Message,
            text: text.into(),
            reply_to: None,
            turn_id: None,
        };
        let encoded = serde_json::to_vec(&queue(&text)).unwrap();
        let queued = record(&intake(&encoded).unwrap());
        assert_eq!(queued.text, text);
        assert_eq!(queued.target_session_id, SESSION);
        let dir = agents_root(environment).join(&config.driver_id);
        let before: Vec<_> = message_ids(&dir)
            .unwrap()
            .into_iter()
            .map(|id| {
                let bytes = fs::read(message_path(&dir, &id)).unwrap();
                (id, bytes)
            })
            .collect();

        let mut input = std::io::Cursor::new(
            serde_json::to_vec(&queue(&"x".repeat(MAX_REQUEST_BYTES))).unwrap(),
        );
        assert!(read_request(&mut input).is_err());
        assert_eq!(input.position(), MAX_REQUEST_BYTES as u64 + 1);
        let mut trailing = serde_json::to_vec(&queue(&text)).unwrap();
        trailing.extend_from_slice(b" {}");
        assert!(intake(&trailing).is_err());
        for text in [
            "\u{1}".repeat(MAX_TEXT_BYTES + 1),
            String::new(),
            "\0".into(),
        ] {
            assert!(intake(&serde_json::to_vec(&queue(&text)).unwrap()).is_err());
        }
        assert_eq!(
            message_ids(&dir).unwrap(),
            before.iter().map(|(id, _)| id.clone()).collect::<Vec<_>>()
        );
        for (id, bytes) in before {
            assert_eq!(fs::read(message_path(&dir, &id)).unwrap(), bytes);
        }
    }

    #[test]
    fn request_schema_is_closed_bounded_and_never_echoes_values() {
        assert!(matches!(
            parse_request(br#"{"op":"protocol_info"}"#).unwrap(),
            ControlRequest::ProtocolInfo {}
        ));
        let invalid: [&[u8]; 8] = [
            br#"{"op":"protocol_info","extra":1}"#,
            br#"{"op":"lookup","message_id":"m","driver_id":"d"}"#,
            br#"{"op":"lookup"}"#,
            br#"{"op":"launch"}"#,
            br#"{"message_id":"m"}"#,
            br#"{"op":"lookup","message_id":"m"} {}"#,
            br#"{"op":"mark_delivery","driver_id":"d","session_id":"s","message_id":"m","outcome":"maybe","error":null}"#,
            br#"{"op":"queue","driver_id":"d","session_id":"s","message_id":"m","action":"steer","text":"t","expected_turn_id":"x"}"#,
        ];
        for request in invalid {
            assert!(
                parse_request(request).is_err(),
                "{}",
                String::from_utf8_lossy(request)
            );
        }
        let error = parse_request(
            br#"{"op":"status","driver_id":"d","session_id":"s","limit":"private prompt text"}"#,
        )
        .unwrap_err();
        assert!(!format!("{error:#}").contains("private prompt text"));

        // Queue flags are optional and may be absent or explicit nulls.
        for request in [
            &br#"{"op":"queue","driver_id":"d","session_id":"s","message_id":"m","action":"message","text":"t"}"#[..],
            br#"{"op":"queue","driver_id":"d","session_id":"s","message_id":"m","action":"interrupt","text":"","reply_to":null,"turn_id":null}"#,
        ] {
            assert!(matches!(
                parse_request(request).unwrap(),
                ControlRequest::Queue {
                    reply_to: None,
                    turn_id: None,
                    ..
                }
            ));
        }

        // The host serializes the same closed type the guest parses.
        let request = ControlRequest::Queue {
            driver_id: new_id(),
            session_id: SESSION.into(),
            message_id: new_id(),
            action: MessageAction::Steer,
            text: "focus".into(),
            reply_to: None,
            turn_id: Some("turn-1".into()),
        };
        let encoded = serde_json::to_vec(&request).unwrap();
        let wire: Value = serde_json::from_slice(&encoded).unwrap();
        assert_eq!(wire["op"], "queue");
        assert_eq!(wire["action"], "steer");
        assert!(wire.get("reply_to").is_none());
        assert!(matches!(
            parse_request(&encoded).unwrap(),
            ControlRequest::Queue {
                turn_id: Some(_),
                ..
            }
        ));
        let request = ControlRequest::MarkDelivery {
            driver_id: new_id(),
            session_id: SESSION.into(),
            message_id: new_id(),
            outcome: DeliveryOutcome::AmbiguousFailure,
            error: Some("stdin ACK lost".into()),
        };
        let wire = serde_json::to_value(&request).unwrap();
        assert_eq!(wire["op"], "mark_delivery");
        assert_eq!(wire["outcome"], "ambiguous_failure");
        let info = serde_json::to_value(ControlRequest::ProtocolInfo {}).unwrap();
        assert_eq!(info, json!({"op": "protocol_info"}));

        let limit = vec![b' '; MAX_REQUEST_BYTES];
        assert_eq!(read_request(&limit[..]).unwrap().len(), MAX_REQUEST_BYTES);
        let oversized = vec![b' '; MAX_REQUEST_BYTES + 1];
        assert!(read_request(&oversized[..]).is_err());
    }

    #[test]
    fn guest_arguments_require_canonical_identity_and_normalized_root() {
        let id = new_id();
        let args = |environment: &str, root: &str| AgentControlArgs {
            environment: environment.into(),
            guest_root: root.into(),
        };
        let environment = guest_environment(&args(&id, "/var/lib/codewire/guest")).unwrap();
        assert_eq!(environment.id(), id);
        assert_eq!(environment.root(), PathBuf::from("/var/lib/codewire/guest"));
        for root in [
            "relative/guest",
            "/",
            "/var/lib/../guest",
            "/var/lib//guest",
            "/var/lib/guest/",
            "/var/./lib/guest",
        ] {
            assert!(guest_environment(&args(&id, root)).is_err(), "{root}");
        }
        assert!(guest_environment(&args(&id.to_uppercase(), "/var/lib/guest")).is_err());
        assert!(guest_environment(&args("host", "/var/lib/guest")).is_err());
    }

    #[test]
    fn prepare_resolves_the_program_in_the_guest_and_retries_idempotently() {
        let guest = guest();
        let environment = &guest.environment;
        let mut config = launch(environment, AgentKind::Codex, false);
        let resolved = std::cell::Cell::new(0);
        let resolve = |agent: AgentKind| {
            resolved.set(resolved.get() + 1);
            resolve_in_guest(agent)
        };
        let prepare = |config: &AgentConfig| {
            let request = parse_request(&serde_json::to_vec(&prepare_request(config)).unwrap())?;
            handle(environment, request, &resolve)
        };

        let first = prepare(&config).unwrap();
        assert_eq!(keys(&first), ["config"]);
        let saved: AgentConfig = serde_json::from_value(first["config"].clone()).unwrap();
        assert_eq!(saved.program, PathBuf::from("/guest/bin/codex"));
        assert_eq!(saved.created_at, config.created_at);
        let dir = agents_root(environment).join(&config.driver_id);
        for path in [
            environment.root(),
            agents_root(environment),
            dir.clone(),
            dir.join("messages"),
        ] {
            assert_eq!(mode(&path), 0o700, "{}", path.display());
        }
        assert_eq!(mode(&dir.join("config.json")), 0o600);

        // A retried request keeps the first guest resolution and timestamp.
        config.created_at = now();
        let retry = prepare(&config).unwrap();
        assert_eq!(retry, first);
        assert_eq!(resolved.get(), 1);

        let mut changed = config.clone();
        changed.model = "gpt-other".into();
        assert!(prepare(&changed).is_err());
        let mut host_program = launch(environment, AgentKind::Claude, false);
        host_program.program = PathBuf::from("/usr/local/bin/claude");
        assert!(prepare(&host_program).is_err());
        let mut implicit_effort = launch(environment, AgentKind::Codex, false);
        implicit_effort.effort = None;
        assert!(prepare(&implicit_effort).is_err());
        let mut other_environment = launch(environment, AgentKind::Claude, false);
        other_environment.environment_id = new_id();
        assert!(prepare(&other_environment).is_err());
        let mut relative = launch(environment, AgentKind::Claude, false);
        relative.working_dir = "workspace".into();
        assert!(prepare(&relative).is_err());
        let mut invalid_name = launch(environment, AgentKind::Claude, false);
        invalid_name.name = "-bad name".into();
        assert!(prepare(&invalid_name).is_err());
        let mut unbound_parent = launch(environment, AgentKind::Claude, false);
        unbound_parent.parent = Some(ParentLink {
            session_id: SESSION.into(),
            driver_id: config.driver_id.clone(),
        });
        assert!(prepare(&unbound_parent).is_err());
        for refused in [
            host_program,
            implicit_effort,
            other_environment,
            relative,
            invalid_name,
            unbound_parent,
        ] {
            assert!(!agents_root(environment).join(&refused.driver_id).exists());
        }
        assert_eq!(resolved.get(), 1);

        // A missing guest CLI fails before any conversation state exists.
        let missing = launch(environment, AgentKind::Claude, false);
        let request =
            parse_request(&serde_json::to_vec(&prepare_request(&missing)).unwrap()).unwrap();
        assert!(handle(environment, request, &|_| anyhow::bail!("not installed")).is_err());
        assert!(!agents_root(environment).join(&missing.driver_id).exists());
    }

    #[test]
    fn workers_bind_only_to_a_canonically_bound_parent() {
        let guest = guest();
        let environment = &guest.environment;
        let (parent, _) = bound(environment, SESSION);
        let mut worker = launch(environment, AgentKind::Claude, false);
        worker.parent = Some(ParentLink {
            session_id: OTHER_SESSION.into(),
            driver_id: parent.driver_id.clone(),
        });
        assert!(run(environment, prepare_request(&worker)).is_err());
        worker.parent = Some(ParentLink {
            session_id: SESSION.into(),
            driver_id: parent.driver_id.clone(),
        });
        let prepared = run(environment, prepare_request(&worker)).unwrap();
        assert_eq!(prepared["config"]["parent"]["driver_id"], parent.driver_id);
    }

    #[test]
    fn bind_publishes_the_initial_message_before_the_binding_and_reuses_retries() {
        let guest = guest();
        let environment = &guest.environment;
        let config = launch(environment, AgentKind::Claude, true);
        run(environment, prepare_request(&config)).unwrap();
        let dir = agents_root(environment).join(&config.driver_id);
        let initial = config.initial_message_id.clone().unwrap();
        let bind = |session: &str, prompt: Option<&str>| {
            run(
                environment,
                json!({"op": "bind", "driver_id": config.driver_id, "session_id": session, "prompt": prompt}),
            )
        };

        assert!(bind(SESSION, None).is_err());
        assert!(bind("session-0B8F4A54-7C43-4B0F-9B6E-0B3C2A1D9E01", Some("plan")).is_err());
        assert!(!dir.join("binding.json").exists());

        // A crash after the initial message but before the binding.
        let mut crashed = MessageRecord::new(
            &config.driver_id,
            SESSION,
            MessageAction::Prompt,
            "plan".into(),
        );
        crashed.id = initial.clone();
        assert!(create_message(&dir, &crashed).unwrap());
        assert!(bind(SESSION, Some("a different plan")).is_err());
        assert!(!dir.join("binding.json").exists());

        let bound = bind(SESSION, Some("plan")).unwrap();
        assert_eq!(keys(&bound), ["binding", "message"]);
        let binding: AgentBinding = serde_json::from_value(bound["binding"].clone()).unwrap();
        assert_eq!(binding.session_id, SESSION);
        assert_eq!(binding.driver_id, config.driver_id);
        let message: MessageRecord = serde_json::from_value(bound["message"].clone()).unwrap();
        assert_eq!(message.id, initial);
        assert_eq!(message.action, MessageAction::Prompt);
        assert_eq!(message.state, MessageState::Requested);
        assert_eq!(message.created_at, crashed.created_at);
        assert_eq!(mode(&dir.join("binding.json")), 0o600);
        assert_eq!(mode(&message_path(&dir, &initial)), 0o600);

        // The driver adopts and settles the prompt; a retry changes nothing.
        update_message(&dir, &initial, |r| {
            r.transition(MessageState::Accepted);
            r.transition(MessageState::Running);
            r.transition(MessageState::Completed);
        })
        .unwrap();
        let retry = bind(SESSION, Some("plan")).unwrap();
        assert_eq!(retry["binding"], bound["binding"]);
        assert_eq!(retry["message"]["state"], "completed");
        assert_eq!(message_ids(&dir).unwrap(), vec![initial.clone()]);

        assert!(bind(OTHER_SESSION, Some("plan")).is_err());
        assert!(bind(SESSION, Some("a different plan")).is_err());
        // A bound conversation never recreates a lost initial message.
        fs::remove_file(message_path(&dir, &initial)).unwrap();
        assert!(bind(SESSION, Some("plan")).is_err());
        assert!(message_ids(&dir).unwrap().is_empty());
    }

    #[test]
    fn queue_retries_preserve_settled_state_and_snapshot_targets() {
        let guest = guest();
        let environment = &guest.environment;
        let (config, dir) = bound(environment, SESSION);
        let driver = config.driver_id.as_str();
        let queue = |id: &str, action: &str, text: &str| {
            run(
                environment,
                queue_request(driver, SESSION, id, action, text),
            )
        };

        let task = new_id();
        let first = queue(&task, "message", "do it").unwrap();
        assert_eq!(keys(&first), ["record"]);
        let created = record(&first);
        assert_eq!(created.state, MessageState::Requested);
        assert_eq!(created.target_session_id, SESSION);
        assert_eq!(mode(&message_path(&dir, &task)), 0o600);
        update_message(&dir, &task, |r| {
            r.transition(MessageState::Accepted);
            r.transition(MessageState::Running);
            r.result = Some("done".into());
            r.transition(MessageState::Completed);
        })
        .unwrap();
        let retry = record(&queue(&task, "message", "do it").unwrap());
        assert_eq!(retry.created_at, created.created_at);
        assert_eq!(retry.state, MessageState::Completed);
        assert_eq!(retry.result.as_deref(), Some("done"));
        assert_eq!(message_ids(&dir).unwrap().len(), 1);
        assert!(queue(&task, "message", "do something else").is_err());
        assert!(queue(&task, "steer", "do it").is_err());
        assert!(
            run(
                environment,
                queue_request(driver, OTHER_SESSION, &new_id(), "message", "x")
            )
            .is_err()
        );
        for (action, text) in [
            ("prompt", "x"),
            ("notification", "x"),
            ("interrupt", "stop"),
            ("message", " "),
        ] {
            assert!(queue(&new_id(), action, text).is_err(), "{action}");
        }

        // Controls are refused exactly as on hosts and leave no record.
        let steer = new_id();
        let interrupt = new_id();
        let refusal = |id: &str, action: &str, text: &str| {
            format!("{:#}", queue(id, action, text).unwrap_err())
        };
        assert!(refusal(&steer, "steer", "focus").contains("has not reported its capabilities"));
        write_state(&dir, &config, false, Some("turn-1"), Some(task.as_str()));
        assert!(refusal(&steer, "steer", "focus").contains("do not support steering"));
        assert!(refusal(&interrupt, "interrupt", "").contains("do not support interrupt"));
        write_state(&dir, &config, true, None, None);
        assert!(refusal(&steer, "steer", "focus").contains("no active turn to steer"));
        assert!(refusal(&interrupt, "interrupt", "").contains("no active turn to interrupt"));
        let mut foreign = config.clone();
        foreign.driver_id = new_id();
        write_state(&dir, &foreign, true, Some("turn-1"), Some(task.as_str()));
        assert!(refusal(&steer, "steer", "focus").contains("does not belong"));
        assert_eq!(message_ids(&dir).unwrap().len(), 1);

        let active = new_id();
        write_state(&dir, &config, true, Some("turn-1"), Some(active.as_str()));
        let steered = record(&queue(&steer, "steer", "focus").unwrap());
        assert_eq!(steered.expected_turn_id.as_deref(), Some("turn-1"));
        let stopped = record(&queue(&interrupt, "interrupt", "").unwrap());
        assert_eq!(
            stopped.expected_active_message_id.as_deref(),
            Some(active.as_str())
        );
        assert_eq!(stopped.expected_turn_id.as_deref(), Some("turn-1"));

        // After the turn ends a retry returns the original target, not a new one.
        write_state(&dir, &config, true, Some("turn-2"), Some(new_id().as_str()));
        let retried = record(&queue(&steer, "steer", "focus").unwrap());
        assert_eq!(retried.created_at, steered.created_at);
        assert_eq!(retried.expected_turn_id.as_deref(), Some("turn-1"));
        let retried = record(&queue(&interrupt, "interrupt", "").unwrap());
        assert_eq!(
            retried.expected_active_message_id.as_deref(),
            Some(active.as_str())
        );
        assert_eq!(message_ids(&dir).unwrap().len(), 3);
    }

    #[test]
    fn queue_honors_reply_and_explicit_turn_flags_like_the_host_cli() {
        let guest = guest();
        let environment = &guest.environment;
        let (config, dir) = bound(environment, SESSION);
        let driver = config.driver_id.as_str();
        let flagged =
            |id: &str, action: &str, text: &str, reply: Option<&str>, turn: Option<&str>| {
                let mut request = queue_request(driver, SESSION, id, action, text);
                request["reply_to"] = json!(reply);
                request["turn_id"] = json!(turn);
                run(environment, request)
            };
        let earlier = new_id();

        let reply = new_id();
        let sent =
            record(&flagged(&reply, "message", "answer", Some(earlier.as_str()), None).unwrap());
        assert_eq!(sent.reply_to.as_deref(), Some(earlier.as_str()));
        assert_eq!(sent.expected_turn_id, None);
        let retry =
            record(&flagged(&reply, "message", "answer", Some(earlier.as_str()), None).unwrap());
        assert_eq!(retry.created_at, sent.created_at);
        assert!(flagged(&reply, "message", "answer", None, None).is_err());
        assert!(flagged(&reply, "message", "answer", Some(new_id().as_str()), None).is_err());

        let refused = new_id();
        for (action, text, reply, turn) in [
            ("message", "x", Some(earlier.to_uppercase()), None),
            ("message", "x", None, Some("turn-1")),
            ("interrupt", "", Some(earlier.clone()), None),
            ("interrupt", "", None, Some("turn-1")),
            ("steer", "x", None, Some("bad turn")),
        ] {
            assert!(
                flagged(&refused, action, text, reply.as_deref(), turn).is_err(),
                "{action} {reply:?} {turn:?}"
            );
        }
        assert!(saved_message(&dir, &refused).unwrap().is_none());

        // An explicit steer target overrides the current turn but still needs
        // the reported steering capability.
        let steer = new_id();
        assert!(flagged(&steer, "steer", "focus", None, Some("turn-7")).is_err());
        write_state(&dir, &config, true, None, None);
        let steered = record(
            &flagged(
                &steer,
                "steer",
                "focus",
                Some(earlier.as_str()),
                Some("turn-7"),
            )
            .unwrap(),
        );
        assert_eq!(steered.expected_turn_id.as_deref(), Some("turn-7"));
        assert_eq!(steered.reply_to.as_deref(), Some(earlier.as_str()));
        write_state(&dir, &config, true, Some("turn-8"), Some(reply.as_str()));
        let implicit_retry =
            record(&flagged(&steer, "steer", "focus", Some(earlier.as_str()), None).unwrap());
        assert_eq!(implicit_retry.expected_turn_id.as_deref(), Some("turn-7"));
        assert!(
            flagged(
                &steer,
                "steer",
                "focus",
                Some(earlier.as_str()),
                Some("turn-8")
            )
            .is_err()
        );
        assert_eq!(message_ids(&dir).unwrap().len(), 2);
    }

    #[test]
    fn delivery_outcomes_preserve_acceptance_and_never_replay_ambiguity() {
        let guest = guest();
        let environment = &guest.environment;
        let (config, dir) = bound(environment, SESSION);
        let driver = config.driver_id.as_str();
        let queued = || {
            let id = new_id();
            run(
                environment,
                queue_request(driver, SESSION, &id, "message", "task"),
            )
            .unwrap();
            id
        };
        let mark = |id: &str, outcome: &str, error: Option<&str>| {
            run(environment, mark_request(driver, id, outcome, error))
        };

        // A lost ACK before acceptance is unknown, and stays unknown.
        let lost = queued();
        let marked = mark(&lost, "ambiguous_failure", Some("stdin ACK lost")).unwrap();
        assert_eq!(keys(&marked), ["record"]);
        let unknown = record(&marked);
        assert_eq!(unknown.state, MessageState::Unknown);
        assert!(unknown.error.as_deref().unwrap().contains("not replayed"));
        for (outcome, error) in [
            ("ambiguous_failure", Some("stdin ACK lost")),
            ("written", None),
        ] {
            assert_eq!(mark(&lost, outcome, error).unwrap(), marked);
        }

        // Receiver acceptance and completion win over a lost pipe ACK.
        let accepted = queued();
        update_message(&dir, &accepted, |r| {
            r.transition(MessageState::Accepted);
        })
        .unwrap();
        let kept = record(&mark(&accepted, "ambiguous_failure", Some("lost")).unwrap());
        assert_eq!(kept.state, MessageState::Accepted);
        assert_eq!(kept.error, None);
        update_message(&dir, &accepted, |r| {
            r.transition(MessageState::Running);
            r.transition(MessageState::Completed);
        })
        .unwrap();
        assert_eq!(
            record(&mark(&accepted, "written", None).unwrap()).state,
            MessageState::Completed
        );

        // A recorded pipe write is not downgraded by a contradictory report.
        let written = queued();
        let piped = mark(&written, "written", None).unwrap();
        assert_eq!(record(&piped).state, MessageState::PipeWritten);
        assert_eq!(
            mark(&written, "definitive_failure", Some("refused")).unwrap(),
            piped
        );

        let refused = queued();
        let error = record(
            &mark(
                &refused,
                "definitive_failure",
                Some("connect \u{1b}[31mrefused"),
            )
            .unwrap(),
        );
        assert_eq!(error.state, MessageState::Error);
        let error = error.error.unwrap();
        assert!(error.contains("not delivered to the driver"));
        assert!(!error.contains('\u{1b}'));

        let pending = queued();
        assert!(mark(&pending, "written", Some("noise")).is_err());
        assert!(mark(&pending, "ambiguous_failure", None).is_err());
        assert!(mark(&pending, "definitive_failure", Some("  ")).is_err());
        assert!(mark(&new_id(), "written", None).is_err());
        let mut other_session = mark_request(driver, &pending, "written", None);
        other_session["session_id"] = json!(OTHER_SESSION);
        assert!(run(environment, other_session).is_err());
        let mut notification = MessageRecord::new(
            driver,
            SESSION,
            MessageAction::Notification,
            "worker finished".into(),
        );
        notification.id = new_id();
        create_message(&dir, &notification).unwrap();
        assert!(mark(&notification.id, "definitive_failure", Some("refused")).is_err());
        assert_eq!(
            load_message(&dir, &pending).unwrap().state,
            MessageState::Requested
        );
        assert_eq!(
            load_message(&dir, &notification.id).unwrap().state,
            MessageState::Requested
        );
    }

    #[test]
    fn status_is_bound_newest_last_and_within_the_response_limit() {
        let guest = guest();
        let environment = &guest.environment;
        let (config, dir) = bound(environment, SESSION);
        let driver = config.driver_id.as_str();
        let status = |session: &str, limit: usize| {
            run(
                environment,
                json!({"op": "status", "driver_id": driver, "session_id": session, "limit": limit}),
            )
        };
        let messages = |response: &Value| -> Vec<MessageRecord> {
            serde_json::from_value(response["messages"].clone()).unwrap()
        };
        let mut ids = Vec::new();
        for second in 0..5 {
            let id = new_id();
            run(
                environment,
                queue_request(driver, SESSION, &id, "message", "task"),
            )
            .unwrap();
            update_message(&dir, &id, |r| {
                r.created_at = format!("2026-01-01T00:00:0{second}.000000Z");
            })
            .unwrap();
            ids.push(id);
        }
        // A worker result with a parent notification stays a plain record.
        update_message(&dir, &ids[4], |r| {
            r.notification = Some(ParentNotification {
                message_id: notification_id(&ids[4]),
                parent_session_id: OTHER_SESSION.into(),
                parent_driver_id: new_id(),
                state: NotificationState::Pending,
                detail: None,
                updated_at: now(),
            });
        })
        .unwrap();

        let response = status(SESSION, 2).unwrap();
        assert_eq!(
            keys(&response),
            [
                "binding",
                "config",
                "driver",
                "messages",
                "peer",
                "peer_error",
                "shutdown",
                "total_messages"
            ]
        );
        assert_eq!(response["total_messages"], 5);
        assert_eq!(response["driver"], Value::Null);
        assert_eq!(response["binding"]["session_id"], SESSION);
        assert_eq!(response["config"]["program"], "/guest/bin/codex");
        let returned: Vec<String> = messages(&response)
            .into_iter()
            .map(|record| record.id)
            .collect();
        assert_eq!(returned, [ids[3].clone(), ids[4].clone()]);
        assert_eq!(status(SESSION, 0).unwrap()["messages"], json!([]));
        assert!(status(SESSION, INBOX_LIMIT + 1).is_err());
        assert!(status(OTHER_SESSION, 2).is_err());
        write_state(&dir, &config, true, Some("turn-1"), Some(ids[4].as_str()));
        assert_eq!(
            status(SESSION, 1).unwrap()["driver"]["current_turn_id"],
            "turn-1"
        );

        // Large results keep the newest records and stay within the bound.
        for id in &ids {
            update_message(&dir, id, |r| {
                r.result = Some("r".repeat(MAX_RESULT_BYTES));
            })
            .unwrap();
        }
        let response = status(SESSION, INBOX_LIMIT).unwrap();
        let returned = messages(&response);
        assert!(!returned.is_empty() && returned.len() < ids.len());
        assert_eq!(returned.last().unwrap().id, ids[4]);
        assert_eq!(response["total_messages"], ids.len());
        assert!(encode_response(&response).unwrap().len() <= MAX_RESPONSE_BYTES);
    }

    #[test]
    fn lookup_is_private_bounded_and_refuses_ambiguous_ids() {
        let guest = guest();
        let environment = &guest.environment;
        let lookup = |id: &str| run(environment, json!({"op": "lookup", "message_id": id}));
        // No guest root yet is a provisioning error, not an absent message.
        assert!(lookup(&new_id()).is_err());

        let (first, first_dir) = bound(environment, SESSION);
        let (second, second_dir) = bound(environment, OTHER_SESSION);
        let id = new_id();
        run(
            environment,
            queue_request(&first.driver_id, SESSION, &id, "message", "task"),
        )
        .unwrap();
        let found = lookup(&id).unwrap();
        assert_eq!(keys(&found), ["binding", "config", "driver_id", "record"]);
        assert_eq!(found["driver_id"], first.driver_id.as_str());
        assert_eq!(found["config"]["driver_id"], first.driver_id.as_str());
        assert_eq!(found["binding"]["session_id"], SESSION);
        assert_eq!(record(&found).id, id);
        assert_eq!(lookup(&new_id()).unwrap(), Value::Null);
        assert!(lookup(&id.to_uppercase()).is_err());
        let get = |driver: &str| {
            run(
                environment,
                json!({"op": "get_message", "driver_id": driver, "message_id": id}),
            )
        };
        let fetched = get(&first.driver_id).unwrap();
        assert_eq!(keys(&fetched), ["record"]);
        assert_eq!(fetched["record"], found["record"]);
        assert!(get(&second.driver_id).is_err());

        // A symlinked alias of a conversation is not a second owner.
        std::os::unix::fs::symlink(&first_dir, agents_root(environment).join(new_id())).unwrap();
        assert_eq!(lookup(&id).unwrap()["driver_id"], first.driver_id.as_str());

        let mut duplicate = MessageRecord::new(
            &second.driver_id,
            OTHER_SESSION,
            MessageAction::Message,
            "task".into(),
        );
        duplicate.id = id.clone();
        create_message(&second_dir, &duplicate).unwrap();
        assert!(format!("{:#}", lookup(&id).unwrap_err()).contains("more than one"));
    }

    #[test]
    fn records_and_directories_must_stay_owner_private() {
        let guest = guest();
        let environment = &guest.environment;
        let (config, dir) = bound(environment, SESSION);
        let driver = config.driver_id.as_str();
        let id = new_id();
        run(
            environment,
            queue_request(driver, SESSION, &id, "message", "task"),
        )
        .unwrap();
        let get = || {
            run(
                environment,
                json!({"op": "get_message", "driver_id": driver, "message_id": id}),
            )
        };
        let status = || {
            run(
                environment,
                json!({"op": "status", "driver_id": driver, "session_id": SESSION, "limit": 10}),
            )
        };
        let set_mode = |path: &Path, mode: u32| {
            fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
        };
        assert!(get().is_ok());

        set_mode(&message_path(&dir, &id), 0o644);
        assert!(get().is_err());
        assert!(status().is_err());
        set_mode(&message_path(&dir, &id), 0o600);

        set_mode(&dir.join("config.json"), 0o640);
        assert!(get().is_err());
        set_mode(&dir.join("config.json"), 0o600);

        set_mode(&dir.join("binding.json"), 0o644);
        assert!(status().is_err());
        assert!(get().is_err());
        set_mode(&dir.join("binding.json"), 0o600);

        let root = environment.root();
        set_mode(&root, 0o755);
        assert!(status().is_err());
        assert!(
            run(
                environment,
                prepare_request(&launch(environment, AgentKind::Codex, false))
            )
            .is_err()
        );
        set_mode(&root, 0o700);
        assert!(status().is_ok());

        // A symlinked conversation directory is refused, not followed.
        let alias = new_id();
        std::os::unix::fs::symlink(&dir, agents_root(environment).join(&alias)).unwrap();
        assert!(
            run(
                environment,
                json!({"op": "get_message", "driver_id": alias, "message_id": id})
            )
            .is_err()
        );
    }

    #[test]
    fn maximum_admitted_record_remains_readable_through_control_responses() {
        let guest = guest();
        let (config, dir) = bound(&guest.environment, SESSION);
        let mut record = MessageRecord::new(
            &config.driver_id,
            SESSION,
            MessageAction::Message,
            "boundary".into(),
        );
        record.state = MessageState::Completed;
        record.native_acknowledged = true;
        record.result = Some(String::new());
        let framing = serde_json::to_vec(&record).unwrap().len();
        record.result = Some("x".repeat(MAX_RECORD_BYTES as usize - framing));
        assert_eq!(
            serde_json::to_vec(&record).unwrap().len(),
            MAX_RECORD_BYTES as usize
        );
        assert!(create_message(&dir, &record).unwrap());
        for op in ["get_message", "lookup"] {
            let mut request = json!({"op": op, "message_id": record.id});
            if op == "get_message" {
                request["driver_id"] = json!(config.driver_id);
            }
            let response = run(&guest.environment, request).unwrap();
            let encoded = encode_response(&response).unwrap();
            assert!(encoded.len() > MAX_RECORD_BYTES as usize);
            assert!(encoded.len() <= MAX_RESPONSE_BYTES);
            let decoded: Value = serde_json::from_slice(&encoded).unwrap();
            let returned: MessageRecord =
                serde_json::from_value(decoded["record"].clone()).unwrap();
            assert_eq!(returned.result, record.result);
            assert!(!returned.result_truncated);
        }
    }

    #[test]
    fn responses_and_errors_are_bounded_single_lines() {
        assert!(encode_response(&json!({"result": "x".repeat(MAX_RESPONSE_BYTES)})).is_err());
        let encoded = encode_response(&json!({"text": "line\nbreak"})).unwrap();
        assert_eq!(encoded.iter().filter(|byte| **byte == b'\n').count(), 1);
        assert_eq!(encoded.last(), Some(&b'\n'));
        assert_eq!(encode_response(&Value::Null).unwrap(), b"null\n");

        let error = sanitize_error(&format!("bad\n\u{1b}[31m{}", "é".repeat(MAX_ERROR_BYTES)));
        assert!(!error.chars().any(char::is_control));
        assert!(error.len() <= MAX_ERROR_BYTES + '…'.len_utf8());

        // Protocol discovery needs no guest state yet.
        let guest = guest();
        let info = run(&guest.environment, json!({"op": "protocol_info"})).unwrap();
        assert_eq!(info, json!({"protocol_version": 1}));
        assert!(!guest.environment.root().exists());
    }
}
