//! Managed noel conversations on trusted Linux hosts. noel, the Rust port of
//! pi, speaks upstream pi's RPC protocol with `--mode rpc`: one JSON command
//! per stdin line, and replies and session events as JSON lines on stdout.
//! Codewire needs two of its extensions, listed in `get_state.rpcExtensions`:
//! `run-id` (every run has a `runId`) and `expected-run-id` (`steer` and
//! `abort` change nothing unless their `expectedRunId` names the active run).
//!
//! | Step | Wire |
//! | --- | --- |
//! | Launch | `noel --mode rpc --session-id S --model PROVIDER/ID [--thinking LEVEL]`; `S` is saved before the first spawn and reopened on every restart |
//! | Startup | `get_state` reports `S`, the model, the requested thinking level and both extensions; then `clear_queue` |
//! | Turn | `clear_queue`, then `prompt {message, requestId}` while idle; the reply's `runId` is the turn ID |
//! | Answer, usage | Text of the last assistant `message_end`; usage summed over the run's assistant `message_end` records |
//! | Turn end | `agent_settled {aborted, runId}`, once per run |
//! | Steer | `steer {message, expectedRunId}`; its reply acknowledges it |
//! | Interrupt | `abort {expectedRunId}`; the reply or the run's `agent_settled` acknowledges it |
use super::*;

const LEGACY: &str = "the installed noel answers JSON-RPC: it is an older build of pi without upstream pi's RPC protocol. Install a noel whose `get_state` reports the run-id and expected-run-id RPC extensions";
const EXTENSIONS: [&str; 2] = ["run-id", "expected-run-id"];
/// Tool arguments that identify a call in the session log.
const ACTIVITY_ARGUMENTS: [&str; 5] = ["command", "path", "pattern", "url", "query"];

/// The launch: pi opens `session` if it exists and creates it otherwise. A
/// requested effort is the thinking level; without one noel keeps its own.
fn arguments<'a>(session: &'a str, model: &'a str, thinking: Option<&'a str>) -> Vec<&'a str> {
    let mut args = vec!["--mode", "rpc", "--session-id", session, "--model", model];
    if let Some(thinking) = thinking {
        args.extend(["--thinking", thinking]);
    }
    args
}

/// The next command ID. Replies echo it.
fn next_id(peer: &mut Peer) -> u64 {
    let id = peer.next_id;
    peer.next_id += 1;
    id
}

/// Writes one command line. A command without an ID gets a reply without one.
async fn send(peer: &mut Peer, id: Option<u64>, kind: &str, fields: Value) -> anyhow::Result<()> {
    let mut command = serde_json::Map::new();
    if let Some(id) = id {
        command.insert("id".into(), json!(id));
    }
    command.insert("type".into(), json!(kind));
    if let Value::Object(fields) = fields {
        command.extend(fields);
    }
    peer.send(&Value::Object(command)).await
}

fn error_text(reply: &Value) -> &str {
    reply
        .get("error")
        .and_then(Value::as_str)
        .unwrap_or("no reason given")
}

/// pi opens no dialogs, but upstream extensions can. The driver cannot answer
/// one interactively, so it declines it rather than leave the run blocked.
async fn decline(peer: &mut Peer, request: &Value) -> anyhow::Result<()> {
    let method = request
        .get("method")
        .and_then(Value::as_str)
        .unwrap_or("dialog");
    log(format!(
        "declined noel {method} dialog under policy: {NOEL_POLICY}"
    ));
    let id = request.get("id").cloned().unwrap_or(Value::Null);
    peer.send(&json!({"type": "extension_ui_response", "id": id, "cancelled": true}))
        .await
}

enum StartupLine {
    Reply(anyhow::Result<Value>),
    Dialog,
    Other,
}

/// Reads one line while a startup command waits for its reply `id`.
fn startup_line(value: &Value, id: u64, kind: &str) -> anyhow::Result<StartupLine> {
    if value.get("jsonrpc").is_some() {
        anyhow::bail!("{LEGACY}");
    }
    Ok(match value.get("type").and_then(Value::as_str) {
        Some("response") if value.get("id").and_then(Value::as_u64) == Some(id) => {
            StartupLine::Reply(
                if value.get("success").and_then(Value::as_bool) == Some(true) {
                    Ok(value.get("data").cloned().unwrap_or(Value::Null))
                } else {
                    Err(anyhow::anyhow!(
                        "noel refused {kind}: {}",
                        error_text(value)
                    ))
                },
            )
        }
        Some("extension_ui_request") => StartupLine::Dialog,
        _ => StartupLine::Other,
    })
}

/// Startup-only command that waits for its reply; the main loop is not
/// running yet. `Peer::call` is shaped for JSON-RPC, so noel has its own.
async fn call(peer: &mut Peer, kind: &str, fields: Value) -> anyhow::Result<Value> {
    let id = next_id(peer);
    send(peer, Some(id), kind, fields).await?;
    let deadline = tokio::time::Instant::now() + NATIVE_RPC_TIMEOUT;
    loop {
        let line = tokio::time::timeout_at(deadline, peer.events.recv())
            .await
            .map_err(|_| {
                anyhow::anyhow!(
                    "noel {kind} did not answer within {}s",
                    NATIVE_RPC_TIMEOUT.as_secs()
                )
            })?;
        match line {
            Some(NativeLine::Json(value)) => match startup_line(&value, id, kind)? {
                StartupLine::Reply(reply) => return reply,
                StartupLine::Dialog => decline(peer, &value).await?,
                StartupLine::Other => {}
            },
            Some(NativeLine::Invalid(reason)) => log(reason),
            Some(NativeLine::Closed(_)) | None => {
                anyhow::bail!("the installed noel exited during {kind}; inspect its stderr above")
            }
        }
    }
}

/// Startup admission: noel must have opened the saved session with the
/// requested model and thinking level, and speak both RPC extensions. Without
/// a requested level, noel keeps its own.
fn admit_state(
    state: &Value,
    session: &str,
    model: &str,
    thinking: Option<&str>,
) -> anyhow::Result<()> {
    let opened = state.get("sessionId").and_then(Value::as_str);
    if opened != Some(session) {
        anyhow::bail!(
            "noel opened session {} instead of saved session {session}; the saved session was not replaced",
            opened.unwrap_or("-")
        );
    }
    let running = match (
        state.pointer("/model/provider").and_then(Value::as_str),
        state.pointer("/model/id").and_then(Value::as_str),
    ) {
        (Some(provider), Some(id)) => Some(format!("{provider}/{id}")),
        _ => None,
    };
    if running.as_deref() != Some(model) {
        anyhow::bail!(
            "noel is not running the requested model {model} (it reports {}); check that noel lists it with `noel --list-models`",
            running.as_deref().unwrap_or("no configured model")
        );
    }
    if let Some(thinking) = thinking {
        let level = state.get("thinkingLevel").and_then(Value::as_str);
        if level != Some(thinking) {
            anyhow::bail!(
                "noel runs {model} at thinking level {} instead of the requested {thinking}; the model may not offer that level",
                level.unwrap_or("-")
            );
        }
    }
    let spoken: Vec<&str> = state
        .get("rpcExtensions")
        .and_then(Value::as_array)
        .map(|names| names.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default();
    if let Some(missing) = EXTENSIONS.iter().find(|name| !spoken.contains(name)) {
        anyhow::bail!(
            "the installed noel does not report the {missing} RPC extension; update noel"
        );
    }
    Ok(())
}

/// How a settled run ends its message: an abort interrupts it, a failed last
/// reply (`stopReason` `error`) fails it, and anything else completes it.
fn outcome(aborted: bool, failure: Option<String>) -> (TurnStatus, Option<String>) {
    match (aborted, failure) {
        (true, _) => (TurnStatus::Interrupted, None),
        (false, Some(failure)) => (TurnStatus::Failed, Some(failure)),
        (false, None) => (TurnStatus::Completed, None),
    }
}

/// Why an assistant message failed, if its `stopReason` is `error`.
fn failure(message: &Value) -> Option<String> {
    (message.get("stopReason").and_then(Value::as_str) == Some("error")).then(|| {
        let reason = message
            .get("errorMessage")
            .and_then(Value::as_str)
            .unwrap_or("no reason given");
        format!("noel's run failed: {reason}")
    })
}

const USAGE_TOKENS: [&str; 5] = ["input", "output", "cacheRead", "cacheWrite", "totalTokens"];

/// Adds one assistant message's usage to its run's total: the token counts in
/// pi's usage shape, `cost` from its `cost.total`, and the number of messages.
fn add_usage(total: &mut Option<Value>, usage: &Value) {
    let total = total.get_or_insert_with(|| {
        json!({"input": 0, "output": 0, "cacheRead": 0, "cacheWrite": 0, "totalTokens": 0, "cost": 0.0, "messages": 0})
    });
    for field in USAGE_TOKENS {
        let sum = total[field]
            .as_u64()
            .unwrap_or(0)
            .saturating_add(usage.get(field).and_then(Value::as_u64).unwrap_or(0));
        total[field] = json!(sum);
    }
    let cost = total["cost"].as_f64().unwrap_or(0.0)
        + usage
            .pointer("/cost/total")
            .and_then(Value::as_f64)
            .unwrap_or(0.0);
    total["cost"] = json!(cost);
    total["messages"] = json!(total["messages"].as_u64().unwrap_or(0).saturating_add(1));
}

/// Session-log lines for what a noel assistant message does: its text and
/// each tool it calls, with the argument that identifies the call.
fn activity(message: &Value) -> Vec<String> {
    let Some(Value::Array(blocks)) = message.get("content") else {
        return Vec::new();
    };
    blocks
        .iter()
        .filter_map(|block| match block.get("type").and_then(Value::as_str) {
            Some("text") => block
                .get("text")
                .and_then(Value::as_str)
                .filter(|text| !text.trim().is_empty())
                .map(|text| format!("says: {}", preview(text))),
            Some("toolCall") => {
                let name = block.get("name").and_then(Value::as_str).unwrap_or("tool");
                let arguments = block.get("arguments");
                let detail = ACTIVITY_ARGUMENTS
                    .iter()
                    .find_map(|key| arguments?.get(key)?.as_str());
                Some(match detail {
                    Some(detail) => format!("tool {name}: {}", preview(detail)),
                    None => format!("tool {name}"),
                })
            }
            _ => None,
        })
        .collect()
}

impl Driver {
    pub(super) fn spawn_noel(&mut self) -> anyhow::Result<Peer> {
        if !cfg!(target_os = "linux") || self.environment.host().is_none() {
            anyhow::bail!("{NOEL_HOST_ONLY}");
        }
        let session = match self.state.native_thread_id.clone() {
            Some(session) => session,
            None => {
                let session = uuid::Uuid::new_v4().to_string();
                self.state.native_thread_id = Some(session.clone());
                self.persist_state()?;
                session
            }
        };
        let args = arguments(&session, &self.config.model, self.config.effort.as_deref());
        Peer::spawn(
            &self.config.program,
            &args,
            &self.config.working_dir,
            self,
            "noel",
        )
    }

    pub(super) async fn initialize_noel(&mut self, peer: &mut Peer) -> anyhow::Result<()> {
        let session = self
            .state
            .native_thread_id
            .clone()
            .context("the noel session ID was not saved before launch")?;
        let state = call(peer, "get_state", json!({})).await?;
        admit_state(
            &state,
            &session,
            &self.config.model,
            self.config.effort.as_deref(),
        )?;
        call(peer, "clear_queue", json!({})).await?;
        self.state.native_thread_established = true;
        self.state.capabilities = AgentCapabilities {
            steer: true,
            interrupt: true,
            note: "noel RPC steer and abort with expectedRunId".into(),
        };
        self.persist_state()?;
        Ok(())
    }

    /// An abort or a failure leaves pi's queue for its next prompt, so the
    /// queue is cleared first: nothing steered toward an earlier message joins
    /// this one.
    pub(super) async fn start_noel_turn(
        &mut self,
        peer: &mut Peer,
        message_id: &str,
        text: &str,
    ) -> anyhow::Result<()> {
        send(peer, None, "clear_queue", json!({})).await?;
        let id = next_id(peer);
        send(
            peer,
            Some(id),
            "prompt",
            json!({"message": text, "requestId": message_id}),
        )
        .await?;
        self.pending
            .insert(id, Pending::TurnStart(message_id.to_owned()));
        Ok(())
    }

    pub(super) async fn steer_noel(
        &mut self,
        peer: &mut Peer,
        record: &MessageRecord,
        run: &str,
    ) -> anyhow::Result<()> {
        let id = next_id(peer);
        // Tracked before the write, so a lost peer records it as unknown.
        self.pending.insert(id, Pending::Steer(record.id.clone()));
        send(
            peer,
            Some(id),
            "steer",
            json!({"message": turn_text(record), "expectedRunId": run}),
        )
        .await
    }

    /// pi answers an abort only after the run settles, so the interrupt joins
    /// the turn when sent: its `agent_settled` acknowledges and ends it.
    pub(super) async fn interrupt_noel(
        &mut self,
        peer: &mut Peer,
        record: &MessageRecord,
        run: Option<String>,
    ) -> anyhow::Result<()> {
        let Some(run) = run else {
            update_message(&self.dir, &record.id, |r| {
                r.fail(
                    MessageState::Error,
                    "the noel run has no ID yet; nothing was interrupted",
                );
            })?;
            return Ok(());
        };
        let id = next_id(peer);
        self.pending
            .insert(id, Pending::Interrupt(record.id.clone()));
        if let Some(active) = self.active.as_mut() {
            active.interrupts.push(record.id.clone());
        }
        send(peer, Some(id), "abort", json!({"expectedRunId": run})).await
    }

    pub(super) async fn on_noel(&mut self, peer: &mut Peer, value: Value) -> anyhow::Result<()> {
        if value.get("type").and_then(Value::as_str) == Some("extension_ui_request") {
            return decline(peer, &value).await;
        }
        self.on_noel_record(&value).await
    }

    async fn on_noel_record(&mut self, value: &Value) -> anyhow::Result<()> {
        match value
            .get("type")
            .and_then(Value::as_str)
            .unwrap_or_default()
        {
            "response" => self.on_noel_response(value).await?,
            "agent_start" => {
                let run = value.get("runId").and_then(Value::as_str);
                if let Some(active) = &self.active
                    && active.turn_id.as_deref() != run
                {
                    log(format!(
                        "noel started run {}; the active run is {}",
                        run.unwrap_or("-"),
                        active.turn_id.as_deref().unwrap_or("-")
                    ));
                }
            }
            "message_end" => {
                let Some(message) = value.get("message").filter(|message| {
                    message.get("role").and_then(Value::as_str) == Some("assistant")
                }) else {
                    return Ok(());
                };
                for line in activity(message) {
                    log(line);
                }
                if let Some(active) = self.active.as_mut() {
                    active.texts.clear();
                    active
                        .texts
                        .extend(content_text(value).filter(|text| !text.is_empty()));
                    active.failure = failure(message);
                    if let Some(usage) = message.get("usage") {
                        add_usage(&mut active.usage, usage);
                    }
                }
            }
            "agent_settled" => self.on_noel_settled(value).await?,
            "auto_retry_start" => log(format!(
                "noel retries ({}/{}): {}",
                value.get("attempt").and_then(Value::as_u64).unwrap_or(0),
                value
                    .get("maxAttempts")
                    .and_then(Value::as_u64)
                    .unwrap_or(0),
                value
                    .get("errorMessage")
                    .and_then(Value::as_str)
                    .unwrap_or("-")
            )),
            _ => {}
        }
        Ok(())
    }

    async fn on_noel_response(&mut self, reply: &Value) -> anyhow::Result<()> {
        let command = reply
            .get("command")
            .and_then(Value::as_str)
            .unwrap_or("command");
        let success = reply.get("success").and_then(Value::as_bool) == Some(true);
        let Some(pending) = reply
            .get("id")
            .and_then(Value::as_u64)
            .and_then(|id| self.pending.remove(&id))
        else {
            // Replies without a pending command: the per-prompt clear_queue,
            // and noel's answer to a declined dialog.
            let dropped = ["/data/steering", "/data/followUp"]
                .iter()
                .filter_map(|path| reply.pointer(path)?.as_array().map(Vec::len))
                .sum::<usize>();
            if !success {
                log(format!("noel refused {command}: {}", error_text(reply)));
            } else if dropped > 0 {
                log(format!(
                    "cleared {dropped} queued noel message(s) left by an earlier run"
                ));
            }
            return Ok(());
        };
        match pending {
            Pending::TurnStart(message_id) => {
                let run = reply
                    .pointer("/data/runId")
                    .and_then(Value::as_str)
                    .filter(|_| {
                        reply.pointer("/data/disposition").and_then(Value::as_str)
                            == Some("started")
                    })
                    .filter(|_| success)
                    .map(str::to_owned);
                let is_active = self
                    .active
                    .as_ref()
                    .is_some_and(|active| active.message_id == message_id);
                let Some(run) = run else {
                    let reason = if success {
                        "noel accepted the prompt without starting a run".to_owned()
                    } else {
                        format!("noel refused the prompt: {}", error_text(reply))
                    };
                    if is_active {
                        return self
                            .finish_turn(TurnStatus::Failed, None, Some(reason), None)
                            .await;
                    }
                    update_message(&self.dir, &message_id, |r| {
                        r.fail(MessageState::Error, reason);
                    })?;
                    return Ok(());
                };
                if let Some(active) = self.active.as_mut()
                    && active.message_id == message_id
                {
                    let run = active.turn_id.get_or_insert(run).clone();
                    self.record_turn(&message_id, &run)?;
                }
            }
            Pending::Steer(message_id) => {
                if !success {
                    update_message(&self.dir, &message_id, |r| {
                        r.fail(
                            MessageState::Error,
                            format!("noel refused the steer: {}", error_text(reply)),
                        );
                    })?;
                    return Ok(());
                }
                // noel answers a steer before it settles the run the steer
                // names, so an accepted steer joins the active run.
                let record = load_message(&self.dir, &message_id)?;
                let joined = match self.active.as_mut() {
                    Some(active)
                        if active.turn_id.is_some()
                            && record.expected_turn_id.as_ref().is_none_or(|expected| {
                                active.turn_id.as_ref() == Some(expected)
                            }) =>
                    {
                        active.steers.push(message_id.clone());
                        active.turn_id.clone()
                    }
                    _ => None,
                };
                update_message(&self.dir, &message_id, |r| {
                    r.native_acknowledged = true;
                    match &joined {
                        Some(run) => r.turn_id = Some(run.clone()),
                        None => {
                            r.turn_id = record.expected_turn_id.clone();
                            r.result = Some(
                                "the steer was accepted for a run that had already ended".into(),
                            );
                            r.transition(MessageState::Completed);
                        }
                    }
                })?;
            }
            Pending::Interrupt(message_id) => {
                if success {
                    update_message(&self.dir, &message_id, |r| {
                        if !r.state.is_terminal() {
                            r.native_acknowledged = true;
                        }
                    })?;
                } else {
                    if let Some(active) = self.active.as_mut() {
                        active.interrupts.retain(|id| *id != message_id);
                    }
                    update_message(&self.dir, &message_id, |r| {
                        r.fail(
                            MessageState::Error,
                            format!("noel refused the interrupt: {}", error_text(reply)),
                        );
                    })?;
                }
            }
        }
        Ok(())
    }

    async fn on_noel_settled(&mut self, settled: &Value) -> anyhow::Result<()> {
        let run = settled.get("runId").and_then(Value::as_str);
        let Some(active) = self.active.as_ref() else {
            log(format!(
                "ignored noel agent_settled for run {} without an active turn",
                run.unwrap_or("-")
            ));
            return Ok(());
        };
        if run.is_none() || active.turn_id.as_deref() != run {
            log(format!(
                "ignored noel agent_settled for run {}; the active run is {}",
                run.unwrap_or("-"),
                active.turn_id.as_deref().unwrap_or("-")
            ));
            return Ok(());
        }
        let aborted = settled.get("aborted").and_then(Value::as_bool) == Some(true);
        if aborted {
            // The settlement acknowledges an abort that noel answers later.
            for id in active.interrupts.clone() {
                update_message(&self.dir, &id, |r| r.native_acknowledged = true)?;
            }
        }
        let (status, error) = outcome(aborted, active.failure.clone());
        let result = active.texts.last().cloned();
        let usage = active.usage.clone();
        self.finish_turn(status, result, error, usage).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SESSION: &str = "0b5f0a52-7d0c-4b8c-9d4c-1f4d7c2e9a10";
    const RUN: &str = "6c1a4f0e-3b2d-4e5f-8a9b-0c1d2e3f4a5b";

    /// noel's own `get_state` reply for `faux/echo`, as the real binary sends it.
    fn state() -> Value {
        json!({
            "model": {"id": "echo", "name": "Faux Echo", "api": "faux", "provider": "faux",
                      "reasoning": false, "contextWindow": 128000},
            "thinkingLevel": "off", "isStreaming": false, "isCompacting": false,
            "steeringMode": "all", "followUpMode": "all",
            "sessionFile": format!("/agent/sessions/{SESSION}.jsonl"), "sessionId": SESSION,
            "autoCompactionEnabled": true, "messageCount": 0, "pendingMessageCount": 0,
            "rpcExtensions": ["run-id", "expected-run-id"]
        })
    }

    /// A peer that runs `script`: `cat` echoes the commands it is sent.
    fn script_peer(script: &str) -> Peer {
        let mut child = tokio::process::Command::new("sh")
            .args(["-c", script])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .unwrap();
        let stdin = child.stdin.take().unwrap();
        let stdout = child.stdout.take().unwrap();
        let (sender, events) = tokio::sync::mpsc::channel(256);
        tokio::spawn(read_native_stdout(stdout, sender));
        Peer {
            child,
            stdin,
            events,
            next_id: 1,
            #[cfg(target_os = "linux")]
            guest: None,
        }
    }

    async fn next_line(peer: &mut Peer) -> Value {
        match tokio::time::timeout(Duration::from_secs(10), peer.events.recv()).await {
            Ok(Some(NativeLine::Json(value))) => value,
            _ => panic!("the driver sent noel no command"),
        }
    }

    struct Harness {
        _temporary: tempfile::TempDir,
        driver: Driver,
    }

    /// A noel driver with private records in a temporary directory and no peer.
    fn harness() -> Harness {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().join("environment");
        let driver_id = uuid::Uuid::new_v4().to_string();
        let dir = root.join("agents").join(&driver_id);
        for path in [&root, &root.join("agents"), &dir, &dir.join("messages")] {
            private_directory(path).unwrap();
        }
        let environment = DriverEnvironment::Guest {
            id: uuid::Uuid::new_v4().to_string(),
            root,
        };
        let started_at = now();
        let driver = Driver {
            #[cfg(target_os = "linux")]
            platform: None,
            config: AgentConfig {
                version: 1,
                driver_id: driver_id.clone(),
                environment_id: environment.id().into(),
                agent: AgentKind::Noel,
                program: PathBuf::from("/usr/local/bin/noel"),
                program_fallback: None,
                model: "faux/echo".into(),
                effort: None,
                working_dir: "/workspace".into(),
                name: String::new(),
                parent: None,
                initial_message_id: None,
                created_at: started_at.clone(),
            },
            environment,
            dir,
            binding: AgentBinding {
                driver_id: driver_id.clone(),
                session_id: "session".into(),
                bound_at: started_at.clone(),
            },
            state: DriverState {
                version: 1,
                driver_id,
                agent: AgentKind::Noel,
                phase: DriverPhase::Idle,
                native_thread_id: Some(SESSION.into()),
                native_thread_established: true,
                current_turn_id: None,
                active_message_id: None,
                queued: 0,
                capabilities: AgentCapabilities {
                    steer: true,
                    interrupt: true,
                    note: String::new(),
                },
                policy: NOEL_POLICY.into(),
                last_error: None,
                started_at: started_at.clone(),
                updated_at: started_at.clone(),
            },
            started_at,
            queue: VecDeque::new(),
            active: None,
            pending: HashMap::new(),
            control_pending: HashMap::new(),
            settled: HashSet::new(),
            stopping: false,
        };
        Harness {
            _temporary: temporary,
            driver,
        }
    }

    impl Harness {
        fn message(&self, action: MessageAction, text: &str) -> MessageRecord {
            let record = MessageRecord::new(
                &self.driver.config.driver_id,
                &self.driver.binding.session_id,
                action,
                text.into(),
            );
            assert!(create_message(&self.driver.dir, &record).unwrap());
            record
        }

        fn update(&self, id: &str, apply: impl FnOnce(&mut MessageRecord)) {
            update_message(&self.driver.dir, id, apply).unwrap();
        }

        fn load(&self, id: &str) -> MessageRecord {
            load_message(&self.driver.dir, id).unwrap()
        }

        /// A message whose noel run is active; `run` is `None` until the
        /// prompt's reply names it.
        fn running(&mut self, text: &str, run: Option<&str>) -> MessageRecord {
            let record = self.message(MessageAction::Message, text);
            self.update(&record.id, |r| {
                r.transition(MessageState::Accepted);
                r.transition(MessageState::Running);
            });
            self.driver.active = Some(ActiveTurn {
                message_id: record.id.clone(),
                text: text.into(),
                turn_id: run.map(str::to_owned),
                texts: Vec::new(),
                steers: Vec::new(),
                interrupts: Vec::new(),
                usage: None,
                acknowledged: false,
                failure: None,
            });
            self.driver.state.active_message_id = Some(record.id.clone());
            self.driver.state.current_turn_id = run.map(str::to_owned);
            record
        }

        async fn record(&mut self, value: Value) {
            self.driver.on_noel_record(&value).await.unwrap();
        }
    }

    fn assistant(text: &str, stop: &str, extra: Value) -> Value {
        let mut message = json!({"role": "assistant", "content": [{"type": "text", "text": text}],
                                 "api": "faux", "provider": "faux", "model": "echo", "stopReason": stop});
        if let (Value::Object(message), Value::Object(extra)) = (&mut message, extra) {
            message.extend(extra);
        }
        json!({"type": "message_end", "message": message})
    }

    #[test]
    fn launch_reopens_the_saved_session_with_the_requested_model_and_level() {
        assert_eq!(
            arguments(SESSION, "faux/echo", None),
            [
                "--mode",
                "rpc",
                "--session-id",
                SESSION,
                "--model",
                "faux/echo"
            ]
        );
        assert_eq!(
            arguments(SESSION, "anthropic/claude-opus-5-5", Some("xhigh")),
            [
                "--mode",
                "rpc",
                "--session-id",
                SESSION,
                "--model",
                "anthropic/claude-opus-5-5",
                "--thinking",
                "xhigh"
            ]
        );
    }

    #[test]
    fn effort_maps_to_thinking_without_a_default_or_ultra() {
        assert_eq!(AgentKind::Noel.name(), "noel");
        assert_eq!(AgentKind::Noel.default_model(), None);
        assert_eq!(agent_effort(AgentKind::Noel, None).unwrap(), None);
        for level in ["low", "medium", "high", "xhigh", "max"] {
            assert_eq!(
                agent_effort(AgentKind::Noel, Some(level))
                    .unwrap()
                    .as_deref(),
                Some(level)
            );
        }
        assert!(agent_effort(AgentKind::Noel, Some("ultra")).is_err());
    }

    #[test]
    fn startup_admits_only_the_saved_session_model_level_and_extensions() {
        admit_state(&state(), SESSION, "faux/echo", None).unwrap();
        let mut high = state();
        high["thinkingLevel"] = json!("high");
        // Without a requested level noel keeps its own.
        admit_state(&high, SESSION, "faux/echo", None).unwrap();
        admit_state(&high, SESSION, "faux/echo", Some("high")).unwrap();
        let refused = |state: &Value, model: &str, thinking: Option<&str>| {
            admit_state(state, SESSION, model, thinking)
                .unwrap_err()
                .to_string()
        };
        // faux/echo has no thinking levels, so noel reports off.
        assert!(
            refused(&state(), "faux/echo", Some("high"))
                .contains("thinking level off instead of the requested high")
        );
        let mut other = state();
        other["sessionId"] = json!("other");
        assert!(refused(&other, "faux/echo", None).contains("instead of saved session"));
        assert!(refused(&state(), "faux/script", None).contains("it reports faux/echo"));
        let mut unconfigured = state();
        unconfigured.as_object_mut().unwrap().remove("model");
        assert!(refused(&unconfigured, "faux/nope", None).contains("no configured model"));
        let mut old = state();
        old["rpcExtensions"] = json!(["run-id"]);
        assert!(refused(&old, "faux/echo", None).contains("expected-run-id RPC extension"));
        old.as_object_mut().unwrap().remove("rpcExtensions");
        assert!(refused(&old, "faux/echo", None).contains("run-id RPC extension"));
    }

    #[test]
    fn startup_reads_its_reply_declines_dialogs_and_refuses_json_rpc() {
        // An older pi build answers `{"id":1,"type":"get_state"}` like this.
        let legacy = json!({"jsonrpc": "2.0", "id": 1, "error": {"code": -32600, "message": "missing method"}});
        let error = startup_line(&legacy, 1, "get_state").err().unwrap();
        assert!(error.to_string().contains("older build of pi"), "{error:#}");
        let reply = |value: Value| match startup_line(&value, 3, "get_state").unwrap() {
            StartupLine::Reply(reply) => Some(reply),
            _ => None,
        };
        let data = json!({"sessionId": SESSION});
        let ok = json!({"id": 3, "type": "response", "command": "get_state", "success": true, "data": data});
        assert_eq!(reply(ok).unwrap().unwrap(), data);
        let failed = json!({"id": 3, "type": "response", "command": "get_state", "success": false, "error": "nope"});
        assert_eq!(
            reply(failed).unwrap().unwrap_err().to_string(),
            "noel refused get_state: nope"
        );
        assert!(reply(json!({"id": 2, "type": "response", "success": true})).is_none());
        assert!(reply(json!({"type": "queue_update", "steering": [], "followUp": []})).is_none());
        let dialog = json!({"type": "extension_ui_request", "id": "d1", "method": "confirm"});
        assert!(matches!(
            startup_line(&dialog, 3, "get_state").unwrap(),
            StartupLine::Dialog
        ));
    }

    #[tokio::test]
    async fn startup_fails_at_once_when_noel_answers_json_rpc() {
        let mut peer = script_peer(
            r#"read -r line; printf '%s\n' '{"jsonrpc":"2.0","id":1,"error":{"code":-32600,"message":"missing method"}}'; sleep 10"#,
        );
        let started = Instant::now();
        let error = call(&mut peer, "get_state", json!({})).await.unwrap_err();
        assert!(error.to_string().contains("older build of pi"), "{error:#}");
        assert!(started.elapsed() < Duration::from_secs(5));
    }

    #[tokio::test]
    async fn startup_declines_a_dialog_and_waits_for_its_own_reply() {
        let mut peer = script_peer(concat!(
            r#"read -r line; printf '%s\n' '{"type":"extension_ui_request","id":"d1","method":"confirm","title":"Proceed?"}'; "#,
            r#"read -r answer; printf '%s\n' "{\"id\":1,\"type\":\"response\",\"command\":\"get_state\",\"success\":true,\"data\":$answer}"; sleep 10"#
        ));
        // The script answers with the dialog response it received as its data.
        let data = call(&mut peer, "get_state", json!({})).await.unwrap();
        assert_eq!(
            data,
            json!({"type": "extension_ui_response", "id": "d1", "cancelled": true})
        );
    }

    #[test]
    fn a_settled_run_maps_to_its_message_outcome() {
        assert!(matches!(
            outcome(false, None),
            (TurnStatus::Completed, None)
        ));
        assert!(matches!(
            outcome(true, None),
            (TurnStatus::Interrupted, None)
        ));
        assert!(matches!(
            outcome(true, Some("failed".into())),
            (TurnStatus::Interrupted, None)
        ));
        let failed = failure(&json!({"stopReason": "error", "errorMessage": "overloaded"}));
        assert_eq!(failed.as_deref(), Some("noel's run failed: overloaded"));
        assert!(matches!(
            outcome(false, failed),
            (TurnStatus::Failed, Some(_))
        ));
        for stop in ["stop", "length", "toolUse", "aborted"] {
            assert_eq!(
                failure(&json!({"stopReason": stop, "errorMessage": "x"})),
                None
            );
        }
    }

    #[test]
    fn usage_is_summed_over_a_runs_assistant_messages() {
        let mut total = None;
        add_usage(
            &mut total,
            &json!({"input": 120, "output": 9, "cacheRead": 4, "cacheWrite": 0, "totalTokens": 129,
                    "cost": {"input": 0, "output": 0, "cacheRead": 0, "cacheWrite": 0, "total": 0}}),
        );
        add_usage(
            &mut total,
            &json!({"input": 200, "output": 21, "cacheWrite": 2, "totalTokens": 221, "cost": {"total": 0.25}}),
        );
        add_usage(&mut total, &json!({}));
        assert_eq!(
            total,
            Some(
                json!({"input": 320, "output": 30, "cacheRead": 4, "cacheWrite": 2,
                        "totalTokens": 350, "cost": 0.25, "messages": 3})
            )
        );
    }

    #[test]
    fn session_log_names_noel_text_and_tool_calls() {
        let message = json!({"role": "assistant", "content": [
            {"type": "thinking", "thinking": "private"},
            {"type": "text", "text": "Reading   the\nnotes."},
            {"type": "toolCall", "id": "call_1", "name": "read", "arguments": {"path": "notes.txt"}},
            {"type": "toolCall", "id": "call_2", "name": "bash", "arguments": {"command": "git status --short", "timeout": 5}},
            {"type": "toolCall", "id": "call_3", "name": "todo", "arguments": {}}
        ]});
        assert_eq!(
            activity(&message),
            [
                "says: Reading the notes.",
                "tool read: notes.txt",
                "tool bash: git status --short",
                "tool todo",
            ]
        );
        assert!(activity(&json!({"role": "assistant", "content": []})).is_empty());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn only_trusted_hosts_launch_noel() {
        let mut h = harness();
        let mut config = h.driver.config.clone();
        config.program = PathBuf::new();
        // The VM, member and platform launches all pass this check.
        let refused = native::validate_launch(&config).unwrap_err().to_string();
        assert!(refused.contains("only on trusted Linux hosts"), "{refused}");
        let refused = h.driver.spawn_noel().err().unwrap().to_string();
        assert!(refused.contains("only on trusted Linux hosts"), "{refused}");
    }

    #[tokio::test]
    async fn a_prompt_reply_names_the_run_and_a_failed_reply_fails_the_message() {
        let mut h = harness();
        let main = h.running("task", None);
        h.driver
            .pending
            .insert(4, Pending::TurnStart(main.id.clone()));
        h.record(
            json!({"id": 4, "type": "response", "command": "prompt", "success": true,
                        "data": {"disposition": "started", "runId": RUN}}),
        )
        .await;
        let started = h.load(&main.id);
        assert!(started.native_acknowledged && started.turn_id.as_deref() == Some(RUN));
        assert_eq!(h.driver.state.current_turn_id.as_deref(), Some(RUN));
        h.record(json!({"type": "agent_start", "runId": RUN})).await;
        let tool = json!({"type": "message_end", "message": {"role": "assistant", "stopReason": "toolUse",
            "content": [{"type": "toolCall", "id": "c1", "name": "read", "arguments": {"path": "notes.txt"}}],
            "usage": {"input": 10, "output": 2, "totalTokens": 12}}});
        h.record(tool).await;
        h.record(json!({"type": "message_end", "message": {"role": "toolResult", "content": [{"type": "text", "text": "alpha"}]}}))
            .await;
        h.record(assistant(
            "",
            "error",
            json!({"errorMessage": "provider overloaded", "usage": {"input": 5, "output": 0, "totalTokens": 5}}),
        ))
        .await;
        h.record(json!({"type": "agent_settled", "aborted": false, "runId": RUN}))
            .await;
        let failed = h.load(&main.id);
        assert_eq!(failed.state, MessageState::Error);
        assert_eq!(
            failed.error.as_deref(),
            Some("noel's run failed: provider overloaded")
        );
        let usage = failed.usage.unwrap();
        assert_eq!(
            (usage["totalTokens"].as_u64(), usage["messages"].as_u64()),
            (Some(17), Some(2))
        );
        assert!(h.driver.active.is_none());

        // A prompt noel refuses fails its message.
        let busy = h.running("second", None);
        h.driver
            .pending
            .insert(5, Pending::TurnStart(busy.id.clone()));
        h.record(
            json!({"id": 5, "type": "response", "command": "prompt", "success": false,
                        "error": "Agent is already processing."}),
        )
        .await;
        let refused = h.load(&busy.id);
        assert_eq!(refused.state, MessageState::Error);
        assert_eq!(
            refused.error.as_deref(),
            Some("noel refused the prompt: Agent is already processing.")
        );
        assert!(h.driver.active.is_none());
    }

    #[tokio::test]
    async fn steer_and_abort_are_acknowledged_by_noel_and_end_with_their_run() {
        let mut h = harness();
        let main = h.running("task", Some(RUN));
        let mut peer = script_peer("cat");

        // cw steer: noel's queued reply acknowledges it; it ends with the run.
        let steer = h.message(MessageAction::Steer, "be brief");
        h.driver.accept(&mut peer, &steer.id).await.unwrap();
        assert_eq!(
            next_line(&mut peer).await,
            json!({"id": 1, "type": "steer", "message": "be brief", "expectedRunId": RUN})
        );
        assert!(!h.load(&steer.id).decided());
        h.record(json!({"type": "queue_update", "steering": ["be brief"], "followUp": []}))
            .await;
        h.record(
            json!({"id": 1, "type": "response", "command": "steer", "success": true,
                        "data": {"disposition": "queued"}}),
        )
        .await;
        let acknowledged = h.load(&steer.id);
        assert!(acknowledged.native_acknowledged && acknowledged.decided());
        assert_eq!(acknowledged.state, MessageState::Running);

        // cw interrupt: pi answers an abort only after the run settles, so the
        // settlement acknowledges it.
        let interrupt = h.message(MessageAction::Interrupt, "");
        h.update(&interrupt.id, |r| {
            r.expected_active_message_id = Some(main.id.clone());
            r.expected_turn_id = Some(RUN.into());
        });
        h.driver.accept(&mut peer, &interrupt.id).await.unwrap();
        assert_eq!(
            next_line(&mut peer).await,
            json!({"id": 2, "type": "abort", "expectedRunId": RUN})
        );
        assert!(!h.load(&interrupt.id).decided());
        h.record(assistant(
            "Once",
            "aborted",
            json!({"errorMessage": "Request was aborted", "usage": {"input": 3, "output": 1, "totalTokens": 4}}),
        ))
        .await;
        h.record(json!({"type": "agent_settled", "aborted": true, "runId": RUN}))
            .await;
        let interrupted = h.load(&main.id);
        assert_eq!(interrupted.state, MessageState::Interrupted);
        assert_eq!(interrupted.result.as_deref(), Some("Once"));
        assert_eq!(h.load(&steer.id).state, MessageState::Interrupted);
        let ended = h.load(&interrupt.id);
        assert!(ended.native_acknowledged && ended.state == MessageState::Completed);
        assert_eq!(
            ended.result,
            Some(format!("turn {RUN} ended as interrupted"))
        );
        // noel's later abort reply changes nothing.
        h.record(json!({"id": 2, "type": "response", "command": "abort", "success": true}))
            .await;
        assert_eq!(h.load(&interrupt.id).updated_at, ended.updated_at);
        assert!(h.driver.active.is_none() && h.driver.pending.is_empty());
    }

    #[tokio::test]
    async fn an_abort_reply_that_comes_first_acknowledges_it() {
        let mut h = harness();
        let main = h.running("task", Some(RUN));
        let interrupt = h.message(MessageAction::Interrupt, "");
        h.update(&interrupt.id, |r| {
            r.transition(MessageState::Accepted);
            r.transition(MessageState::Running);
        });
        h.driver
            .pending
            .insert(7, Pending::Interrupt(interrupt.id.clone()));
        h.driver
            .active
            .as_mut()
            .unwrap()
            .interrupts
            .push(interrupt.id.clone());
        h.record(json!({"id": 7, "type": "response", "command": "abort", "success": true}))
            .await;
        let acknowledged = h.load(&interrupt.id);
        assert!(acknowledged.native_acknowledged && acknowledged.decided());
        assert_eq!(acknowledged.state, MessageState::Running);
        // Another run's settlement is not this turn's.
        h.record(json!({"type": "agent_settled", "aborted": true, "runId": "another-run"}))
            .await;
        assert_eq!(h.load(&main.id).state, MessageState::Running);
        h.record(json!({"type": "agent_settled", "aborted": true, "runId": RUN}))
            .await;
        assert_eq!(h.load(&main.id).state, MessageState::Interrupted);
        assert_eq!(h.load(&interrupt.id).state, MessageState::Completed);
    }

    /// A busy noel conversation with `next` waiting in the Codewire queue, and
    /// an interrupt of its run: the stop's when `stop`, else `cw interrupt`'s.
    async fn interrupted_with_a_queued_message(
        stop: bool,
    ) -> (Harness, Peer, MessageRecord, MessageRecord, MessageRecord) {
        let mut h = harness();
        let main = h.running("task", Some(RUN));
        let mut peer = script_peer("cat");
        let queued = h.message(MessageAction::Message, "next");
        h.driver.accept(&mut peer, &queued.id).await.unwrap();
        assert_eq!(h.driver.queue, std::slice::from_ref(&queued.id));
        let mut interrupt = MessageRecord::new(
            &h.driver.config.driver_id,
            &h.driver.binding.session_id,
            MessageAction::Interrupt,
            String::new(),
        );
        if stop {
            interrupt.id = stop_interrupt_id(&main.id);
        }
        interrupt.expected_active_message_id = Some(main.id.clone());
        interrupt.expected_turn_id = Some(RUN.into());
        assert!(create_message(&h.driver.dir, &interrupt).unwrap());
        h.driver.accept(&mut peer, &interrupt.id).await.unwrap();
        assert_eq!(
            next_line(&mut peer).await,
            json!({"id": 1, "type": "abort", "expectedRunId": RUN})
        );
        h.record(json!({"type": "agent_settled", "aborted": true, "runId": RUN}))
            .await;
        assert_eq!(h.load(&main.id).state, MessageState::Interrupted);
        assert_eq!(h.load(&interrupt.id).state, MessageState::Completed);
        (h, peer, main, queued, interrupt)
    }

    #[tokio::test]
    async fn a_stop_interrupt_ends_the_run_and_starts_nothing_before_the_stop() {
        let (mut h, mut peer, _, queued, _) = interrupted_with_a_queued_message(true).await;
        // The host daemon signals the session next: the queued message stays
        // accepted for the next start instead of starting and being cut off.
        h.driver.start_next(&mut peer).await.unwrap();
        assert!(h.driver.active.is_none());
        assert_eq!(h.load(&queued.id).state, MessageState::Accepted);
        assert_eq!(h.driver.queue, std::slice::from_ref(&queued.id));
        assert_eq!(h.driver.state.phase, DriverPhase::Idle);
        assert!(
            tokio::time::timeout(Duration::from_millis(200), peer.events.recv())
                .await
                .is_err(),
            "noel was sent another command"
        );
    }

    #[tokio::test]
    async fn cw_interrupt_still_starts_the_next_queued_message() {
        let (mut h, mut peer, _, queued, _) = interrupted_with_a_queued_message(false).await;
        h.driver.start_next(&mut peer).await.unwrap();
        assert_eq!(h.load(&queued.id).state, MessageState::Running);
        assert_eq!(next_line(&mut peer).await, json!({"type": "clear_queue"}));
        assert_eq!(
            next_line(&mut peer).await,
            json!({"id": 2, "type": "prompt", "message": "next", "requestId": queued.id})
        );
    }

    #[tokio::test]
    async fn steer_and_interrupt_need_the_active_run_and_a_late_steer_is_refused() {
        let mut h = harness();
        let main = h.running("task", None);
        let mut peer = script_peer("cat");

        // Until the prompt's reply names the run, nothing is interrupted.
        let early = h.message(MessageAction::Interrupt, "");
        h.update(&early.id, |r| {
            r.expected_active_message_id = Some(main.id.clone())
        });
        h.driver.accept(&mut peer, &early.id).await.unwrap();
        let early = h.load(&early.id);
        assert_eq!(early.state, MessageState::Error);
        assert!(early.error.unwrap().contains("native ID"));
        h.driver.active.as_mut().unwrap().turn_id = Some(RUN.into());

        // A steer for another run is refused before it reaches noel.
        let fenced = h.message(MessageAction::Steer, "elsewhere");
        h.update(&fenced.id, |r| {
            r.expected_turn_id = Some("another-run".into())
        });
        h.driver.accept(&mut peer, &fenced.id).await.unwrap();
        assert_eq!(h.load(&fenced.id).state, MessageState::Error);

        // A steer that reaches noel after the run settled is refused by noel.
        let late = h.message(MessageAction::Steer, "too late");
        h.driver.accept(&mut peer, &late.id).await.unwrap();
        assert_eq!(
            next_line(&mut peer).await,
            json!({"id": 1, "type": "steer", "message": "too late", "expectedRunId": RUN})
        );
        h.record(assistant("[faux/echo] task", "stop", json!({})))
            .await;
        h.record(json!({"type": "agent_settled", "aborted": false, "runId": RUN}))
            .await;
        let completed = h.load(&main.id);
        assert_eq!(completed.state, MessageState::Completed);
        assert_eq!(completed.result.as_deref(), Some("[faux/echo] task"));
        h.record(
            json!({"id": 1, "type": "response", "command": "steer", "success": false,
                        "error": format!("expectedRunId {RUN} does not match: no run is active")}),
        )
        .await;
        let late = h.load(&late.id);
        assert_eq!(late.state, MessageState::Error);
        assert!(
            late.error
                .unwrap()
                .starts_with("noel refused the steer: expectedRunId")
        );
    }
}
