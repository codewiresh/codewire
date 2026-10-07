//! Host-side native guest control. Only transient public Run calls cross the
//! boundary; durable records and provider protocols remain inside the guest.
use super::*;
mod verified_runtime;

const RUNTIME_ROOT: &str = codewire_local_vmm::artifact::CW_RUNTIME_ROOT;
const STATE_ROOT: &str = "/home/codewire/.local/state/codewire/managed-agents-v1";
const HELPER_TIMEOUT: Duration = Duration::from_secs(30);
const QUERY_INTERVAL: Duration = Duration::from_millis(500);
const MANAGED_STOP_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct MessageLocation {
    version: u32,
    environment_id: String,
    driver_id: String,
    message_id: String,
    session_id: Option<String>,
    executable: String,
}

#[derive(Clone)]
struct Guest {
    target: EnvironmentSessionTarget,
    id: String,
    root: String,
    executable: String,
}

fn hex_identity(value: &str, len: usize) -> bool {
    value.len() == len
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn index_root() -> anyhow::Result<PathBuf> {
    Ok(ResolvePaths::from_env(&OsEnv)?
        .platform_config_dir
        .join("native-managed-messages-v1"))
}

fn location_path(message_id: &str) -> anyhow::Result<PathBuf> {
    Ok(index_root()?.join(format!("{}.json", canonical_uuid(message_id)?)))
}

fn save_location(
    guest: &Guest,
    driver_id: &str,
    message_id: &str,
    session_id: Option<&str>,
) -> anyhow::Result<()> {
    let location = MessageLocation {
        version: 1,
        environment_id: guest.id.clone(),
        driver_id: canonical_uuid(driver_id)?,
        message_id: canonical_uuid(message_id)?,
        session_id: session_id.map(str::to_owned),
        executable: guest.executable.clone(),
    };
    private_directory(&index_root()?)?;
    let path = location_path(message_id)?;
    if let Some(old) = read_optional::<MessageLocation>(&path)?
        && (old.version != 1
            || old.environment_id != location.environment_id
            || old.driver_id != location.driver_id
            || old.message_id != location.message_id
            || old.executable != location.executable
            || old
                .session_id
                .as_ref()
                .is_some_and(|id| location.session_id.as_ref() != Some(id)))
    {
        anyhow::bail!("managed native message binding changed");
    }
    write_private_json(&path, &location)
}

fn checked_executable(executable: &str) -> anyhow::Result<()> {
    let digest = executable
        .strip_prefix(&format!("{RUNTIME_ROOT}/"))
        .and_then(|path| path.strip_suffix("/cw"))
        .context("managed guest command does not name a pinned runtime")?;
    if !hex_identity(digest, 64) {
        anyhow::bail!("managed guest runtime has an invalid digest");
    }
    Ok(())
}

impl Guest {
    fn new(target: EnvironmentSessionTarget, executable: String) -> anyhow::Result<Self> {
        let EnvironmentSessionTarget::NativeLocal { environment_id, .. } = &target else {
            anyhow::bail!("managed native control requires a Linux VM");
        };
        let id = canonical_uuid(environment_id)?;
        checked_executable(&executable)?;
        Ok(Self {
            root: format!("{STATE_ROOT}/{id}"),
            id,
            target,
            executable,
        })
    }

    async fn admit_retained(
        target: EnvironmentSessionTarget,
        executable: String,
    ) -> anyhow::Result<Self> {
        let guest = Self::new(target, executable)?;
        let catalog =
            super::super::super::native::native_environment_managed_runtime_catalog(&guest.id)
                .await?;
        if !catalog
            .runtimes
            .iter()
            .any(|runtime| guest.executable == runtime.executable())
        {
            anyhow::bail!(
                "retained managed session helper is absent from the running VM runtime catalog"
            );
        }
        Ok(guest)
    }

    async fn control(&self, request: Value) -> anyhow::Result<Value> {
        let request = serde_json::to_vec(&request)?;
        let data = native_environment_data_client(&self.id).await?;
        let response = data
            .exec_with_stdin(
                verified_runtime::command(
                    &self.executable,
                    &[
                        "_agent-control".into(),
                        "--environment".into(),
                        self.id.clone(),
                        "--guest-root".into(),
                        self.root.clone(),
                    ],
                )?,
                "/workspace",
                Vec::<(String, String)>::new(),
                request,
                HELPER_TIMEOUT,
            )
            .await
            .context(
                "guest control transport failed; its effect may be unknown and is not replayed",
            )?;
        if response.exit_code != 0 {
            // This helper emits only its own bounded errors, never a provider's
            // launch environment or authentication material.
            anyhow::bail!(
                "guest managed control failed: {}",
                String::from_utf8_lossy(&response.stderr)
            );
        }
        if !response.stderr.is_empty() {
            anyhow::bail!("guest managed control returned unexpected stderr");
        }
        serde_json::from_slice(&response.stdout)
            .context("guest managed control returned invalid JSON")
    }

    async fn get_message(
        &self,
        driver_id: &str,
        message_id: &str,
    ) -> anyhow::Result<MessageRecord> {
        let response = self
            .control(json!({"op":"get_message", "driver_id":driver_id, "message_id":message_id}))
            .await?;
        let record: MessageRecord = serde_json::from_value(
            response
                .get("record")
                .cloned()
                .context("guest control omitted its message")?,
        )?;
        if record.id != message_id || record.driver_id != driver_id {
            anyhow::bail!("guest managed message identity changed");
        }
        Ok(record)
    }

    async fn status(&self, driver_id: &str, session_id: &str) -> anyhow::Result<Value> {
        self.control(json!({"op":"status", "driver_id":driver_id, "session_id":session_id, "limit":INBOX_LIMIT})).await
    }
}

async fn resolve(
    target: EnvironmentSessionTarget,
    requested: &str,
) -> anyhow::Result<(Guest, EnvironmentSessionView, String)> {
    let view = match select_environment_session(&target, Some(requested)).await? {
        SessionSelection::Select(view) => *view,
        SessionSelection::Create => anyhow::bail!("session {requested:?} not found"),
    };
    let (environment_id, driver_id) =
        driver_identity(&view.command).context("session is not a managed agent conversation")?;
    let executable = retained_runtime(&view.command)?;
    let guest = Guest::admit_retained(target, executable).await?;
    if environment_id != guest.id
        || !view
            .command
            .windows(2)
            .any(|pair| pair[0] == "--guest-root" && pair[1] == guest.root)
    {
        anyhow::bail!("managed guest session binding does not match this environment");
    }
    Ok((guest, view, driver_id))
}

fn retained_runtime(command: &[String]) -> anyhow::Result<String> {
    let position = command
        .iter()
        .position(|arg| arg == DRIVER_COMMAND)
        .context("managed guest session omitted its driver command")?;
    let executable = position
        .checked_sub(1)
        .and_then(|i| command.get(i))
        .context("managed guest session omitted its pinned runtime")?;
    checked_executable(executable)?;
    if position != 1 && command != verified_runtime::command(executable, &command[position..])? {
        anyhow::bail!("managed guest launcher does not match the verified runtime contract");
    }
    Ok(executable.clone())
}

fn check_launch_generation(view: &EnvironmentSessionView, expected: u64) -> anyhow::Result<()> {
    if expected == 0 || view.launch_generation == 0 {
        anyhow::bail!("managed guest lifecycle requires daemon launch generation support");
    }
    if view.launch_generation != expected {
        anyhow::bail!("managed guest launch generation changed; lifecycle request refused");
    }
    Ok(())
}

fn checked_peer_status(
    status: &Value,
    environment_id: &str,
    driver_id: &str,
    session_id: &str,
) -> anyhow::Result<guest_custody::PeerReceipt> {
    let peer: guest_custody::PeerReceipt = serde_json::from_value(
        status
            .get("peer")
            .cloned()
            .context("guest status omitted peer custody")?,
    )?;
    let state: DriverState = serde_json::from_value(
        status
            .get("driver")
            .cloned()
            .context("guest status omitted driver state")?,
    )?;
    if peer.version != 1
        || peer.identity.environment_id != environment_id
        || peer.identity.driver_id != driver_id
        || peer.identity.session_id != session_id
        || state.version != 1
        || state.driver_id != driver_id
        || state.started_at != peer.identity.driver_started_at
    {
        anyhow::bail!("guest peer custody does not match the retained driver instance");
    }
    canonical_uuid(&peer.identity.instance_id)?;
    Ok(peer)
}

fn checked_shutdown(
    status: &Value,
    peer: &guest_custody::PeerReceipt,
) -> anyhow::Result<Option<guest_custody::ShutdownRecord>> {
    let record = status
        .get("shutdown")
        .filter(|value| !value.is_null())
        .cloned()
        .map(serde_json::from_value::<guest_custody::ShutdownRecord>)
        .transpose()?;
    if let Some(record) = &record {
        canonical_uuid(&record.operation_id)?;
        if record.version != 1 || record.peer != peer.identity {
            anyhow::bail!("guest shutdown operation belongs to another peer instance");
        }
    }
    Ok(record)
}

/// Requires both the guardian's family proof and the durable driver's exit.
/// A driver or provider PID disappearing alone cannot authorize restart.
async fn wait_clean_driver(
    guest: &Guest,
    driver_id: &str,
    session_id: &str,
    identity: &guest_custody::PeerIdentity,
    shutdown: Option<&guest_custody::ShutdownRecord>,
    expected_launch_generation: u64,
) -> anyhow::Result<EnvironmentSessionView> {
    let deadline = Instant::now() + MANAGED_STOP_TIMEOUT;
    loop {
        let request = match shutdown {
            Some(record) => json!({"op":"get_shutdown", "driver_id":driver_id,
                "session_id":session_id, "operation_id":record.operation_id,
                "instance_id":identity.instance_id}),
            None => json!({"op":"peer_status", "driver_id":driver_id, "session_id":session_id}),
        };
        let status = guest.control(request).await?;
        let peer = checked_peer_status(&status, &guest.id, driver_id, session_id)?;
        if peer.identity != *identity {
            anyhow::bail!("guest peer instance changed while waiting for cleanup");
        }
        if let Some(expected) = shutdown {
            let record =
                checked_shutdown(&status, &peer)?.context("guest shutdown journal is missing")?;
            if record.operation_id != expected.operation_id {
                anyhow::bail!("guest shutdown operation identity changed");
            }
        }
        let view = guest.target.get(session_id).await?;
        check_launch_generation(&view, expected_launch_generation)?;
        if !peer.cleanup_unknown && peer.finished_at.is_some() && session_is_terminal(&view) {
            if view.cleanup_unknown {
                anyhow::bail!("durable driver cleanup is unknown; restart is fenced");
            }
            return Ok(view);
        }
        if Instant::now() >= deadline {
            anyhow::bail!(
                "managed shutdown is not confirmed; guardian custody is retained and restart is fenced"
            );
        }
        tokio::time::sleep(QUERY_INTERVAL).await;
    }
}

pub(super) async fn stop(
    target: EnvironmentSessionTarget,
    selected: &EnvironmentSessionView,
) -> anyhow::Result<EnvironmentSessionView> {
    check_launch_generation(selected, selected.launch_generation)?;
    let (guest, view, driver_id) = resolve(target, &selected.session_id).await?;
    check_launch_generation(&view, selected.launch_generation)?;
    let status = guest
        .control(json!({"op":"peer_status", "driver_id":driver_id, "session_id":view.session_id}))
        .await?;
    let peer = checked_peer_status(&status, &guest.id, &driver_id, &view.session_id)?;
    // A new driver can publish its peer after the earlier session read. Its
    // daemon generation is admitted first; combine this reread with the helper's
    // atomic expected-peer comparison so a delayed caller cannot stop it.
    check_launch_generation(
        &guest.target.get(&view.session_id).await?,
        selected.launch_generation,
    )?;
    if session_is_terminal(&view) {
        return wait_clean_driver(
            &guest,
            &driver_id,
            &view.session_id,
            &peer.identity,
            None,
            selected.launch_generation,
        )
        .await;
    }
    let shutdown = match checked_shutdown(&status, &peer)? {
        Some(existing) => existing,
        None => {
            let operation_id = uuid::Uuid::new_v4().to_string();
            let status = guest
                .control(json!({"op":"shutdown", "driver_id":driver_id,
                "session_id":view.session_id, "operation_id":operation_id, "peer":peer.identity}))
                .await
                .context(
                    "shutdown request may have been persisted; inspect the session before retrying",
                )?;
            let actual_peer =
                checked_peer_status(&status, &guest.id, &driver_id, &view.session_id)?;
            if actual_peer.identity != peer.identity {
                anyhow::bail!("guest peer changed while requesting shutdown");
            }
            let record = checked_shutdown(&status, &actual_peer)?
                .context("shutdown response omitted the operation")?;
            if record.operation_id != operation_id {
                anyhow::bail!("shutdown response changed the operation identity");
            }
            record
        }
    };
    if shutdown.accepted_at.is_none() && shutdown.finished_at.is_none() {
        // One bounded hint; the persisted request is also adopted by the
        // driver timer. A lost input ACK is never retried automatically.
        let _ = guest
            .target
            .send_input(
                &view.session_id,
                shutdown_control_line(&driver_id, &shutdown.operation_id)?,
            )
            .await;
    }
    wait_clean_driver(
        &guest,
        &driver_id,
        &view.session_id,
        &peer.identity,
        Some(&shutdown),
        selected.launch_generation,
    )
    .await
}

pub(super) async fn restart(
    target: EnvironmentSessionTarget,
    selected: &EnvironmentSessionView,
) -> anyhow::Result<EnvironmentSessionView> {
    stop(target.clone(), selected).await?;
    let EnvironmentSessionTarget::NativeLocal { environment_id, .. } = &target else {
        anyhow::bail!("managed native restart requires a Linux VM");
    };
    let restarted = native_environment_session_client(environment_id)
        .await?
        .restart_with_generation(&selected.session_id, Some(selected.launch_generation))
        .await
        .context(
            "managed restart response was not confirmed; inspect the session before retrying",
        )?;
    Ok(platform_environment_session_view(restarted))
}

async fn provision(target: EnvironmentSessionTarget) -> anyhow::Result<Guest> {
    let EnvironmentSessionTarget::NativeLocal { environment_id, .. } = &target else {
        anyhow::bail!("managed native control requires a Linux VM");
    };
    let runtime = super::super::super::native::native_environment_managed_runtime(environment_id)
        .await
        .context("VM requires an image-derived cw asset supplied in its boot bundle")?;
    let guest = Guest::new(target, runtime.executable())?;
    let info = guest.control(json!({"op":"protocol_info"})).await?;
    if info.get("protocol_version").and_then(Value::as_u64)
        != Some(u64::from(GUEST_AGENT_PROTOCOL_VERSION))
    {
        anyhow::bail!("boot cw image has an incompatible control protocol");
    }
    Ok(guest)
}

pub(super) async fn run(
    target: EnvironmentSessionTarget,
    args: EnvironmentRunArgs,
) -> anyhow::Result<()> {
    let agent = match args.agent.as_deref() {
        Some("codex") => AgentKind::Codex,
        Some("claude") => AgentKind::Claude,
        _ => anyhow::bail!("native managed conversations support --agent codex or --agent claude"),
    };
    if args.tty || !args.command.is_empty() {
        anyhow::bail!(
            "managed conversations launch the selected agent without a terminal or COMMAND"
        );
    }
    let EnvironmentSessionTarget::NativeLocal { environment_id, .. } = &target else {
        unreachable!()
    };
    require_native_agent_profile(
        environment_id,
        if agent == AgentKind::Codex {
            "codex"
        } else {
            "anthropic"
        },
    )
    .await?;
    let model = args
        .model
        .clone()
        .unwrap_or_else(|| agent.default_model().into());
    validate_token("model", &model)?;
    let effort = agent_effort(agent, args.effort.as_deref())?;
    if let Some(prompt) = &args.prompt {
        validate_text(prompt)?;
    }
    let launch_env = parse_env_overrides(&args.env)?;
    let working_dir = args
        .workdir
        .clone()
        .unwrap_or_else(|| target.default_working_dir());
    let parent = if let Some(requested) = args.parent.as_deref().and_then(trimmed_str) {
        let (_, view, driver_id) = resolve(target.clone(), requested).await?;
        if !session_running(&view) {
            anyhow::bail!("the managed guest parent must be running");
        }
        Some(ParentLink {
            session_id: view.session_id,
            driver_id,
        })
    } else {
        None
    };
    let guest = provision(target).await?;
    let driver_id = uuid::Uuid::new_v4().to_string();
    let initial_message_id = args
        .prompt
        .as_ref()
        .map(|_| uuid::Uuid::new_v4().to_string());
    let config = AgentConfig {
        version: 1,
        driver_id: driver_id.clone(),
        environment_id: guest.id.clone(),
        agent,
        program: PathBuf::new(),
        model: model.clone(),
        effort: effort.clone(),
        working_dir: working_dir.clone(),
        name: args.name.clone().unwrap_or_default(),
        parent: parent.clone(),
        initial_message_id: initial_message_id.clone(),
        created_at: now(),
    };
    guest
        .control(json!({"op":"prepare", "config":config}))
        .await?;
    if let Some(id) = &initial_message_id {
        save_location(&guest, &driver_id, id, None)?;
    }
    let command = verified_runtime::command(
        &guest.executable,
        &[
            DRIVER_COMMAND.into(),
            "--environment".into(),
            guest.id.clone(),
            "--driver-id".into(),
            driver_id.clone(),
            "--guest-root".into(),
            guest.root.clone(),
        ],
    )?;
    let session = guest
        .target
        .launch(
            command,
            working_dir,
            launch_env,
            false,
            config.name,
            parent.map(|parent| parent.session_id).unwrap_or_default(),
        )
        .await?;
    if let Some(id) = &initial_message_id {
        save_location(&guest, &driver_id, id, Some(&session.session_id))?;
    }
    let bound = guest.control(json!({"op":"bind", "driver_id":driver_id, "session_id":session.session_id, "prompt":args.prompt})).await
        .with_context(|| format!("guest driver {} launched but binding result is unknown; inspect its session before retrying", session.session_id))?;
    let mut message = bound
        .get("message")
        .filter(|value| !value.is_null())
        .cloned()
        .map(serde_json::from_value::<MessageRecord>)
        .transpose()?;
    let mut wait_error = None;
    if let Some(id) = &initial_message_id {
        let accepted = await_acceptance(&guest, &driver_id, id).await?;
        if args.detach || accepted.state.is_terminal() {
            message = Some(accepted);
        } else {
            let (record, end) = wait_record(&guest, &driver_id, id, RUN_WAIT_TIMEOUT).await?;
            wait_error = wait_failure(&record, &end);
            message = Some(record);
        }
    }
    match args.output {
        OutputFormat::Json => println!(
            "{}",
            serde_json::to_string_pretty(&json!({"session":session, "driver_id":driver_id,
            "agent":agent.name(), "model":model, "effort":effort, "message":message}))?
        ),
        OutputFormat::Text => {
            if let Some(record) = &message {
                if args.detach {
                    print_message_summary(record, OutputFormat::Text)?;
                } else {
                    print_message_result(record, OutputFormat::Text)?;
                }
            } else {
                println!("{}", session.session_id);
            }
        }
    }
    if let Some(error) = wait_error {
        return Err(error);
    }
    if let Some(record) = &message
        && let Some(error) = message_failure(record)
    {
        return Err(error);
    }
    Ok(())
}

fn record_from_view(mut value: Value) -> anyhow::Result<MessageRecord> {
    if let Some(object) = value.as_object_mut() {
        object.remove("notification_receiver_state");
    }
    serde_json::from_value(value).map_err(Into::into)
}

pub(super) async fn message(
    target: EnvironmentSessionTarget,
    session: &str,
    text: &str,
    reply_to: Option<String>,
    turn_id: Option<String>,
    steer: bool,
    output: OutputFormat,
) -> anyhow::Result<()> {
    let (guest, view, driver_id) = resolve(target, session).await?;
    if !session_running(&view) {
        anyhow::bail!(
            "managed guest conversation is {}; it cannot accept messages",
            view.state
        );
    }
    let id = uuid::Uuid::new_v4().to_string();
    save_location(&guest, &driver_id, &id, Some(&view.session_id))?;
    let queued = guest.control(json!({"op":"queue", "driver_id":driver_id, "session_id":view.session_id, "message_id":id,
        "action":if steer { "steer" } else { "message" }, "text":text, "reply_to":reply_to, "turn_id":turn_id})).await
        .with_context(|| format!("message {id} queue result is unknown; inspect that same ID before retrying"))?;
    let record = deliver(&guest, &view, &driver_id, &id, queued).await?;
    print_message_summary(&record, output)?;
    if let Some(error) = message_failure(&record) {
        return Err(error);
    }
    Ok(())
}

pub(super) async fn interrupt(
    target: EnvironmentSessionTarget,
    session: &str,
    output: OutputFormat,
) -> anyhow::Result<()> {
    let (guest, view, driver_id) = resolve(target, session).await?;
    if !session_running(&view) {
        anyhow::bail!("managed guest conversation is not running");
    }
    let id = uuid::Uuid::new_v4().to_string();
    save_location(&guest, &driver_id, &id, Some(&view.session_id))?;
    let queued = guest.control(json!({"op":"queue", "driver_id":driver_id, "session_id":view.session_id, "message_id":id,
        "action":"interrupt", "text":"", "reply_to":null, "turn_id":null})).await?;
    let record = deliver(&guest, &view, &driver_id, &id, queued).await?;
    print_message_summary(&record, output)?;
    if let Some(error) = message_failure(&record) {
        return Err(error);
    }
    Ok(())
}

async fn deliver(
    guest: &Guest,
    view: &EnvironmentSessionView,
    driver_id: &str,
    id: &str,
    queued: Value,
) -> anyhow::Result<MessageRecord> {
    let record: MessageRecord = serde_json::from_value(
        queued
            .get("record")
            .cloned()
            .context("guest queue omitted its record")?,
    )?;
    if record.id != id
        || record.driver_id != driver_id
        || record.target_session_id != view.session_id
    {
        anyhow::bail!("guest queue returned a different message binding");
    }
    if record.state.rank() >= MessageState::Accepted.rank() {
        return await_acceptance(guest, driver_id, id).await;
    }
    let result = guest
        .target
        .send_input(&view.session_id, control_line(driver_id, id)?)
        .await;
    let (outcome, error) = match &result {
        Ok(()) => ("written", None),
        // Public transport failures after an input write are conservatively
        // ambiguous; no status code can establish receiver nonacceptance.
        Err(error) => ("ambiguous_failure", Some(format!("{error:#}"))),
    };
    guest
        .control(
            json!({"op":"mark_delivery", "driver_id":driver_id, "session_id":view.session_id,
                        "message_id":id, "outcome":outcome, "error":error}),
        )
        .await
        .with_context(|| format!("message {id} delivery is unknown; no automatic replay"))?;
    await_acceptance(guest, driver_id, id).await
}

async fn await_acceptance(
    guest: &Guest,
    driver_id: &str,
    id: &str,
) -> anyhow::Result<MessageRecord> {
    let deadline = Instant::now() + ACCEPT_TIMEOUT;
    loop {
        let record = guest.get_message(driver_id, id).await?;
        if record.decided() {
            return Ok(record);
        }
        if Instant::now() >= deadline {
            anyhow::bail!(
                "message {id} is {} and undecided; no automatic replay",
                record.state.name()
            );
        }
        tokio::time::sleep(QUERY_INTERVAL).await;
    }
}

pub(super) async fn inbox(
    target: EnvironmentSessionTarget,
    session: &str,
    output: OutputFormat,
) -> anyhow::Result<()> {
    let (guest, view, driver_id) = resolve(target, session).await?;
    let mut status = guest.status(&driver_id, &view.session_id).await?;
    let config: AgentConfig = serde_json::from_value(
        status
            .get("config")
            .cloned()
            .context("guest status omitted config")?,
    )?;
    config.validate(&guest.id, &driver_id)?;
    let binding: AgentBinding = serde_json::from_value(
        status
            .get("binding")
            .cloned()
            .context("guest status omitted binding")?,
    )?;
    if binding.driver_id != driver_id || binding.session_id != view.session_id {
        anyhow::bail!("guest status binding changed");
    }
    if let Some(messages) = status.get("messages").and_then(Value::as_array) {
        for message in messages {
            let record = record_from_view(message.clone())?;
            if record.driver_id != driver_id || record.target_session_id != view.session_id {
                anyhow::bail!("guest inbox message binding changed");
            }
            save_location(&guest, &driver_id, &record.id, Some(&view.session_id))?;
        }
    }
    status["environment_id"] = json!(guest.id);
    status["session_id"] = json!(view.session_id);
    status["session_state"] = json!(view.state);
    status["driver_id"] = json!(driver_id);
    status["agent"] = json!(config.agent.name());
    status["model"] = json!(config.model);
    status["effort"] = json!(config.effort);
    status["parent"] = json!(config.parent);
    status["messages_total"] = status.get("total_messages").cloned().unwrap_or(Value::Null);
    match output {
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&status)?),
        OutputFormat::Text => {
            println!(
                "{}\t{}\t{}",
                session_label(&view),
                config.agent.name(),
                view.state
            );
            if let Some(messages) = status.get("messages").and_then(Value::as_array) {
                for message in messages {
                    let record = record_from_view(message.clone())?;
                    println!(
                        "{}\t{}\t{}",
                        record.id,
                        record.action.name(),
                        record.state.name()
                    );
                }
            }
        }
    }
    Ok(())
}

async fn wait_record(
    guest: &Guest,
    driver_id: &str,
    id: &str,
    timeout: Duration,
) -> anyhow::Result<(MessageRecord, WaitEnd)> {
    let deadline = Instant::now() + timeout;
    let mut next_session_check = Instant::now();
    loop {
        let record = guest.get_message(driver_id, id).await?;
        if record.state.is_terminal() {
            return Ok((record, WaitEnd::Terminal));
        }
        let current = Instant::now();
        if current >= deadline {
            return Ok((record, WaitEnd::TimedOut));
        }
        if current >= next_session_check {
            next_session_check = current + SESSION_CHECK_INTERVAL;
            let view = guest.target.get(&record.target_session_id).await?;
            if session_finished(&view) {
                let record = guest.get_message(driver_id, id).await?;
                let end = if record.state.is_terminal() {
                    WaitEnd::Terminal
                } else {
                    WaitEnd::SessionEnded(view.state)
                };
                return Ok((record, end));
            }
        }
        tokio::time::sleep(QUERY_INTERVAL.min(deadline.saturating_duration_since(current))).await;
    }
}

pub(super) async fn wait(
    globals: &Globals,
    message_id: &str,
    timeout: Duration,
    output: OutputFormat,
) -> anyhow::Result<bool> {
    let location = read_optional::<MessageLocation>(&location_path(message_id)?)?;
    let Some(location) = location else {
        return Ok(false);
    };
    if location.version != 1 || location.message_id != message_id {
        anyhow::bail!("native message index identity is invalid");
    }
    canonical_uuid(&location.environment_id)?;
    canonical_uuid(&location.driver_id)?;
    let target =
        resolve_environment_session_target(globals, Some(&location.environment_id)).await?;
    let guest = Guest::admit_retained(target, location.executable).await?;
    if guest.id != location.environment_id {
        anyhow::bail!("the managed message environment was replaced");
    }
    let (record, end) = wait_record(&guest, &location.driver_id, message_id, timeout).await?;
    if location
        .session_id
        .as_ref()
        .is_some_and(|id| record.target_session_id != *id)
    {
        anyhow::bail!("managed message session identity changed");
    }
    print_message_result(&record, output)?;
    if let Some(error) = wait_failure(&record, &end).or_else(|| message_failure(&record)) {
        return Err(error);
    }
    Ok(true)
}

/// Recover only from the selected native VM's existing pinned runtime. This
/// never boots a VM, provisions a helper or searches unrelated environments.
pub(super) async fn recover_and_wait(
    globals: &Globals,
    message_id: &str,
    timeout: Duration,
    output: OutputFormat,
) -> anyhow::Result<bool> {
    let paths = ResolvePaths::from_env(&OsEnv)?;
    if selected_host_environment()?.is_some() {
        return Ok(false);
    }
    if let Ok(current) = config::current_target(&paths.mesh_data_dir)
        && current.kind != "local"
    {
        return Ok(false);
    }
    let target = resolve_environment_session_target(globals, None).await?;
    if !matches!(target, EnvironmentSessionTarget::NativeLocal { .. }) {
        return Ok(false);
    }
    let mut sessions = target.list().await?;
    if sessions.len() > MAX_DRIVERS_SCANNED {
        anyhow::bail!("selected VM has too many sessions for bounded message recovery");
    }
    sessions.sort_by(|left, right| right.started_at.cmp(&left.started_at));
    let mut runtimes = HashSet::new();
    for view in sessions {
        let Some((environment_id, _)) = driver_identity(&view.command) else {
            continue;
        };
        let executable = retained_runtime(&view.command)?;
        let guest = Guest::admit_retained(target.clone(), executable.clone()).await?;
        if environment_id != guest.id
            || !view
                .command
                .windows(2)
                .any(|pair| pair[0] == "--guest-root" && pair[1] == guest.root)
        {
            anyhow::bail!("retained managed runtime binding changed during recovery");
        }
        if !runtimes.insert(executable.clone()) {
            continue;
        }
        if runtimes.len() > 16 {
            anyhow::bail!(
                "selected VM has too many runtime revisions for bounded message recovery"
            );
        }
        let found = guest
            .control(json!({"op":"lookup", "message_id":message_id}))
            .await?;
        if found.is_null() {
            continue;
        }
        let config: AgentConfig = serde_json::from_value(
            found
                .get("config")
                .cloned()
                .context("lookup omitted config")?,
        )?;
        let driver_id = canonical_uuid(
            found
                .get("driver_id")
                .and_then(Value::as_str)
                .context("lookup omitted driver ID")?,
        )?;
        config.validate(&guest.id, &driver_id)?;
        let binding: AgentBinding = serde_json::from_value(
            found
                .get("binding")
                .cloned()
                .context("lookup omitted binding")?,
        )?;
        let record: MessageRecord = serde_json::from_value(
            found
                .get("record")
                .cloned()
                .context("lookup omitted record")?,
        )?;
        if binding.driver_id != driver_id
            || record.driver_id != driver_id
            || record.id != message_id
            || record.target_session_id != binding.session_id
        {
            anyhow::bail!("recovered managed message binding changed");
        }
        let (bound_guest, _, bound_driver) = resolve(target.clone(), &binding.session_id).await?;
        if bound_driver != driver_id || bound_guest.id != guest.id {
            anyhow::bail!("recovered message does not match its retained daemon session");
        }
        save_location(
            &bound_guest,
            &driver_id,
            message_id,
            Some(&binding.session_id),
        )?;
        return wait(globals, message_id, timeout, output).await;
    }
    Ok(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn custody_status() -> Value {
        json!({
            "driver": {
                "version":1, "driver_id":"00000000-0000-4000-8000-000000000002",
                "agent":"codex", "phase":"idle", "native_thread_id":"thread", "native_thread_established":true,
                "current_turn_id":null, "active_message_id":null, "queued":0,
                "capabilities":{"steer":true,"interrupt":true,"note":"fixture"}, "policy":"fixture",
                "last_error":null, "started_at":"2026-10-01T00:00:00Z", "updated_at":"2026-10-01T00:00:00Z"
            },
            "peer": {
                "version":1,
                "identity": {
                    "environment_id":"00000000-0000-4000-8000-000000000001",
                    "driver_id":"00000000-0000-4000-8000-000000000002",
                    "session_id":"session-00000000-0000-4000-8000-000000000003",
                    "instance_id":"00000000-0000-4000-8000-000000000004",
                    "driver_started_at":"2026-10-01T00:00:00Z",
                    "boot_id":"00000000-0000-4000-8000-000000000005",
                    "driver_pid":100, "driver_start_ticks":50
                },
                "guardian_pid":101, "guardian_start_ticks":51, "provider_pid":102,
                "cleanup_unknown":true, "finished_at":null, "exit_code":null, "error":null
            },
            "shutdown":null
        })
    }

    fn validate_custody(status: &Value) -> anyhow::Result<guest_custody::PeerReceipt> {
        checked_peer_status(
            status,
            "00000000-0000-4000-8000-000000000001",
            "00000000-0000-4000-8000-000000000002",
            "session-00000000-0000-4000-8000-000000000003",
        )
    }

    #[test]
    fn peer_custody_refuses_rebinding_and_preserves_unknown() {
        let status = custody_status();
        assert!(validate_custody(&status).unwrap().cleanup_unknown);
        for path in [
            "/peer/identity/environment_id",
            "/peer/identity/driver_id",
            "/peer/identity/session_id",
            "/peer/identity/driver_started_at",
            "/driver/driver_id",
            "/driver/started_at",
        ] {
            let mut changed = status.clone();
            *changed.pointer_mut(path).unwrap() = json!("another-instance");
            assert!(validate_custody(&changed).is_err(), "{path}");
        }
        let mut future = status;
        future["peer"]["authority"] = json!("unexpected");
        assert!(validate_custody(&future).is_err());
    }

    #[test]
    fn shutdown_status_cannot_confirm_another_peer_instance() {
        let mut status = custody_status();
        let peer = validate_custody(&status).unwrap();
        status["shutdown"] = json!({"version":1,"operation_id":"00000000-0000-4000-8000-000000000006",
            "peer":peer.identity, "requested_at":"2026-10-01T00:00:00Z", "accepted_at":null,
            "finished_at":null,"cleanup_unknown":true,"error":null});
        assert!(
            checked_shutdown(&status, &peer)
                .unwrap()
                .unwrap()
                .cleanup_unknown
        );
        status["shutdown"]["peer"]["instance_id"] = json!("00000000-0000-4000-8000-000000000007");
        assert!(checked_shutdown(&status, &peer).is_err());
    }

    #[test]
    fn guest_runtime_rejects_unpinned_paths_and_digest_aliases() {
        assert!(checked_executable(&format!("{RUNTIME_ROOT}/{}/cw", "a".repeat(64))).is_ok());
        for path in [
            "/usr/local/bin/cw".into(),
            format!("{RUNTIME_ROOT}/../cw"),
            format!("{RUNTIME_ROOT}/{}/cw", "A".repeat(64)),
            format!("{RUNTIME_ROOT}/{}/cw/other", "a".repeat(64)),
        ] {
            assert!(checked_executable(&path).is_err(), "{path}");
        }
    }

    #[test]
    fn guest_artifact_rejects_other_architectures_and_dynamic_dependencies() {
        let mut elf = vec![0_u8; 136];
        elf[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
        elf[16..18].copy_from_slice(&2_u16.to_le_bytes());
        let machine = codewire_local_vmm::artifact::CW_RUNTIME_ELF_MACHINE;
        elf[18..20].copy_from_slice(&machine.to_le_bytes());
        elf[32..40].copy_from_slice(&64_u64.to_le_bytes());
        elf[54..56].copy_from_slice(&56_u16.to_le_bytes());
        elf[56..58].copy_from_slice(&1_u16.to_le_bytes());
        elf[64..68].copy_from_slice(&1_u32.to_le_bytes());
        assert!(codewire_local_vmm::artifact::validate_static_cw(&elf).is_ok());
        let mut other = elf.clone();
        // EM_X86_64 and EM_AARCH64: the other architecture is refused.
        let foreign = if machine == 62 { 183_u16 } else { 62_u16 };
        other[18..20].copy_from_slice(&foreign.to_le_bytes());
        assert!(codewire_local_vmm::artifact::validate_static_cw(&other).is_err());
        let mut loader = elf.clone();
        loader[64..68].copy_from_slice(&3_u32.to_le_bytes());
        assert!(codewire_local_vmm::artifact::validate_static_cw(&loader).is_err());
        let mut needed = elf.clone();
        needed[64..68].copy_from_slice(&2_u32.to_le_bytes());
        needed[72..80].copy_from_slice(&120_u64.to_le_bytes());
        needed[96..104].copy_from_slice(&16_u64.to_le_bytes());
        needed[120..128].copy_from_slice(&1_i64.to_le_bytes());
        assert!(codewire_local_vmm::artifact::validate_static_cw(&needed).is_err());
        elf[32..40].copy_from_slice(&u64::MAX.to_le_bytes());
        assert!(codewire_local_vmm::artifact::validate_static_cw(&elf).is_err());
        assert!(codewire_local_vmm::artifact::validate_static_cw(b"#!/bin/sh\n").is_err());
    }
}
