//! Managed noel conversations on trusted Linux hosts. noel, the Rust port of
//! pi, speaks upstream pi's RPC protocol with `--mode rpc`: one JSON command
//! per stdin line, and replies and session events as JSON lines on stdout.
//! Codewire needs two of its extensions, listed in `get_state.rpcExtensions`:
//! `run-id` (every run has a `runId`) and `expected-run-id` (`steer` and
//! `abort` change nothing unless their `expectedRunId` names the active run).
//! Two more let it resume a run a crash interrupted: `request-id` (a run
//! remembers the `requestId` of the prompt that started it) and `resume-run`
//! (`get_state.lastRun` and `resume_run`).
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
//! | Recovery | After startup's `clear_queue`, `get_state.lastRun` decides a message still running when the driver or noel died (see [`resolve`]) |
use super::*;

const LEGACY: &str = "the installed noel answers JSON-RPC: it is an older build of pi without upstream pi's RPC protocol. Install a noel whose `get_state` reports the run-id and expected-run-id RPC extensions";
const EXTENSIONS: [&str; 2] = ["run-id", "expected-run-id"];
/// Without both, a run a crash interrupted ends unknown, as for Codex and
/// Claude: `request-id` binds a run to its message and `resume-run` reports
/// and continues it.
const RESUME_EXTENSIONS: [&str; 2] = ["request-id", "resume-run"];
/// A message's run is resumed after a crash at most this often, so a run
/// that keeps crashing noel or the driver ends unknown. A resume after its
/// environment's takedown paused it is not a crash and does not count.
const MAX_RESUMES: u32 = 3;
/// How long a message set aside for the startup handshake waits for noel to
/// decide it: one startup command's bound, for the whole handshake.
const RESUME_DEADLINE: Duration = NATIVE_RPC_TIMEOUT;
/// Why `recover()` gives up on a message that was running, for every agent.
/// The record says "{RESTARTED}; {RESTARTED_TAIL}".
const RESTARTED: &str = "the driver restarted while this was in flight";
const RESTARTED_TAIL: &str = "outcome unknown; not replayed";
/// Why a paused message that its next start cannot resume ends unknown:
/// "{PAUSED}; {RESTARTED_TAIL}".
const PAUSED: &str = "paused when its environment stopped";
/// How `lose_peer` ends the active message: "{reason}; {LOST_TAIL}".
const LOST_TAIL: &str = "the turn outcome is unknown and is not replayed";
/// noel saves no reply and no reason for a failed run, so a failure whose
/// settlement the driver missed has only this.
const MISSED_FAILURE: &str =
    "noel's run failed while the driver was down; noel records no reason for a failed run";
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

/// noel answered a command with `success: false`: it is running and
/// changed nothing, unlike a command it never answered.
#[derive(Debug)]
struct Refused {
    kind: String,
    error: String,
}

impl std::fmt::Display for Refused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "noel refused {}: {}", self.kind, self.error)
    }
}

impl std::error::Error for Refused {}

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
                    Err(Refused {
                        kind: kind.into(),
                        error: error_text(value).into(),
                    }
                    .into())
                },
            )
        }
        Some("extension_ui_request") => StartupLine::Dialog,
        _ => StartupLine::Other,
    })
}

/// Startup-only command that waits for its reply until `deadline`; the main
/// loop is not running yet. `Peer::call` is shaped for JSON-RPC, so noel has
/// its own.
async fn call(
    peer: &mut Peer,
    kind: &str,
    fields: Value,
    deadline: tokio::time::Instant,
) -> anyhow::Result<Value> {
    let id = next_id(peer);
    let budget = deadline.saturating_duration_since(tokio::time::Instant::now());
    send(peer, Some(id), kind, fields).await?;
    loop {
        let line = tokio::time::timeout_at(deadline, peer.events.recv())
            .await
            .map_err(|_| {
                anyhow::anyhow!(
                    "noel {kind} did not answer within {:.1}s",
                    budget.as_secs_f64()
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
    let spoken = extensions(state);
    if let Some(missing) = EXTENSIONS.iter().find(|name| !spoken.contains(name)) {
        anyhow::bail!(
            "the installed noel does not report the {missing} RPC extension; update noel"
        );
    }
    Ok(())
}

/// `get_state.rpcExtensions`.
fn extensions(state: &Value) -> Vec<&str> {
    state
        .get("rpcExtensions")
        .and_then(Value::as_array)
        .map(|names| names.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default()
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

/// A message whose run stopped while it was running, because the driver or
/// noel died or its environment was taken down, set aside until noel's
/// journal decides it.
#[derive(Clone, Debug)]
pub(super) struct SetAside {
    message_id: String,
    /// The run Codewire recorded for it, once noel's prompt reply arrived.
    turn_id: Option<String>,
    /// Crash resumes counted so far.
    resumed: u32,
    /// Its environment's takedown paused it: resuming it is no crash resume.
    paused: bool,
    /// An explicit stop or restart recorded its interrupt for it: it ends,
    /// and is never resumed.
    stopped: bool,
    /// Interrupts the driver had accepted for it. They end the run; it is
    /// never resumed.
    interrupts: Vec<String>,
    /// When the handshake must have decided it.
    deadline: tokio::time::Instant,
    /// Why its run stopped, and how its record ends if it ends unknown:
    /// "{cause}; {tail}".
    cause: String,
    tail: &'static str,
}

/// noel's crash recovery in the driver.
#[derive(Debug, Default)]
pub(super) struct Recovery {
    set_aside: Option<SetAside>,
    /// The message noel was restarted for: once per message.
    respawned_for: Option<String>,
}

impl Recovery {
    /// The message waiting for the startup handshake to decide it.
    pub(super) fn set_aside_message(&self) -> Option<&str> {
        self.set_aside
            .as_ref()
            .map(|aside| aside.message_id.as_str())
    }

    /// The environment's takedown leaves the set-aside message paused for
    /// the next start, which sets it aside again.
    pub(super) fn forget_set_aside(&mut self) {
        self.set_aside = None;
    }
}

/// How `respawn_noel` answered noel's exit.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum Respawn {
    /// noel was started again and the handshake decided the run.
    Started,
    /// A signal that stops it ended noel, as one stopping its whole session
    /// does: never answered with a restart.
    Signalled,
    /// Not started again: the caller loses the peer, as before.
    No,
}

/// `get_state.lastRun`, the session's last run.
#[derive(Debug, PartialEq)]
struct LastRun {
    run_id: String,
    request_id: Option<String>,
    status: String,
    phase: Option<String>,
    /// `pendingTools`: what resuming does with each tool call the stop cut
    /// off.
    pending: Vec<String>,
}

fn last_run(state: &Value) -> Option<LastRun> {
    let last = state.get("lastRun")?;
    let text = |key: &str| last.get(key).and_then(Value::as_str).map(str::to_owned);
    let pending = last
        .get("pendingTools")
        .and_then(Value::as_array)
        .map(|tools| {
            tools
                .iter()
                .map(|tool| {
                    let name = tool.get("name").and_then(Value::as_str).unwrap_or("tool");
                    if tool.get("replaySafe").and_then(Value::as_bool) == Some(true) {
                        format!("{name} runs again")
                    } else {
                        format!("{name} is reported interrupted, not run again")
                    }
                })
                .collect()
        })
        .unwrap_or_default();
    Some(LastRun {
        run_id: text("runId")?,
        request_id: text("requestId"),
        status: text("status")?,
        phase: text("phase"),
        pending,
    })
}

/// How a run that ended while the driver was down ended.
#[derive(Clone, Copy, Debug, PartialEq)]
enum RunEnd {
    Completed,
    Failed,
    Aborted,
}

impl RunEnd {
    fn name(self) -> &'static str {
        match self {
            Self::Completed => "completed",
            Self::Failed => "failed",
            Self::Aborted => "aborted",
        }
    }
}

/// What the driver does with a set-aside message `M`, by noel's last run.
/// The run is bound to `M` when its `requestId` is `M`'s ID (and its run ID
/// the one Codewire recorded, if any).
#[derive(Debug, PartialEq)]
enum Resolution {
    /// Bound, running or interrupted, no interrupt accepted for `M`, and
    /// either paused by its environment's takedown or resumed after a crash
    /// fewer than [`MAX_RESUMES`] times: `resume_run`. `saved_reply` when the
    /// run stopped after its last reply was saved, so resuming only
    /// completes it.
    Resume { run: String, saved_reply: bool },
    /// Bound, running or interrupted, an interrupt accepted for `M` or an
    /// explicit stop's interrupt recorded for it: `abort`, and `M` ends
    /// interrupted.
    Abort { run: String },
    /// Bound and ended: the driver missed its settlement.
    Ended { run: String, end: RunEnd },
    /// Anything else, or a noel without both resume extensions: `M` ends
    /// unknown, as for Codex and Claude. An interrupted last run is aborted,
    /// so it is never resumed later.
    Unknown { abort: Option<String> },
}

fn resolve(aside: &SetAside, last: Option<&LastRun>, resumable: bool) -> Resolution {
    let Some(last) = last.filter(|_| resumable) else {
        return Resolution::Unknown { abort: None };
    };
    let interrupted = (last.status == "interrupted").then(|| last.run_id.clone());
    let bound = last.request_id.as_deref() == Some(aside.message_id.as_str())
        && aside.turn_id.as_ref().is_none_or(|run| *run == last.run_id);
    if !bound {
        return Resolution::Unknown { abort: interrupted };
    }
    let run = last.run_id.clone();
    match last.status.as_str() {
        "running" | "interrupted" if aside.stopped || !aside.interrupts.is_empty() => {
            Resolution::Abort { run }
        }
        "running" | "interrupted" if aside.paused || aside.resumed < MAX_RESUMES => {
            Resolution::Resume {
                saved_reply: interrupted.is_some() && last.phase.is_none(),
                run,
            }
        }
        "completed" => Resolution::Ended {
            run,
            end: RunEnd::Completed,
        },
        "failed" => Resolution::Ended {
            run,
            end: RunEnd::Failed,
        },
        "aborted" => Resolution::Ended {
            run,
            end: RunEnd::Aborted,
        },
        _ => Resolution::Unknown { abort: interrupted },
    }
}

/// Whether noel ended because a signal asked it to stop, as the host daemon
/// signals a whole session it stops: noel exits 128 + SIGTERM or SIGHUP, and
/// dies by SIGINT. Such a stop is never answered with a restart.
fn stopped_by_signal(status: std::process::ExitStatus) -> bool {
    use std::os::unix::process::ExitStatusExt as _;
    const STOPS: [i32; 3] = [libc::SIGTERM, libc::SIGHUP, libc::SIGINT];
    status
        .signal()
        .is_some_and(|signal| STOPS.contains(&signal))
        || status
            .code()
            .is_some_and(|code| STOPS.iter().any(|signal| code == 128 + signal))
}

/// `cw inbox` notes a message whose run noel resumed: after a crash, counted,
/// and after its environment stopped.
pub(super) fn resumed_note(record: &MessageRecord) -> String {
    let crashes = match record.native_resumed {
        0 => String::new(),
        1 => " (resumed by noel)".into(),
        times => format!(" (resumed by noel {times} times)"),
    };
    let paused = if record.pause.is_some() && record.state != MessageState::Paused {
        " (resumed after its environment stopped)"
    } else {
        ""
    };
    format!("{crashes}{paused}")
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

    /// The startup handshake, also after a respawn. `clear_queue` precedes
    /// any resume, so a steer noel saved before a crash never joins the
    /// resumed run.
    pub(super) async fn initialize_noel(&mut self, peer: &mut Peer) -> anyhow::Result<()> {
        let session = self
            .state
            .native_thread_id
            .clone()
            .context("the noel session ID was not saved before launch")?;
        let state = call(peer, "get_state", json!({}), self.handshake_deadline()).await?;
        admit_state(
            &state,
            &session,
            &self.config.model,
            self.config.effort.as_deref(),
        )?;
        call(peer, "clear_queue", json!({}), self.handshake_deadline()).await?;
        let resume = RESUME_EXTENSIONS
            .iter()
            .all(|name| extensions(&state).contains(name));
        self.state.native_thread_established = true;
        self.state.capabilities = AgentCapabilities {
            steer: true,
            interrupt: true,
            resume,
            note: if resume {
                "noel RPC steer and abort with expectedRunId; resume_run continues a run a crash interrupted".into()
            } else {
                "noel RPC steer and abort with expectedRunId; this noel cannot resume a run a crash interrupted".into()
            },
        };
        self.persist_state()?;
        self.decide_set_aside(peer, &state).await
    }

    /// When the next startup command must be answered: its own bound, or
    /// sooner while a message waits for the handshake.
    fn handshake_deadline(&self) -> tokio::time::Instant {
        let own = tokio::time::Instant::now() + NATIVE_RPC_TIMEOUT;
        self.noel
            .set_aside
            .as_ref()
            .map_or(own, |aside| own.min(aside.deadline))
    }

    /// `recover()`: a message that was running when the driver stopped, or
    /// that its environment's takedown paused, is set aside for the startup
    /// handshake instead of ending unknown at once, and an interrupt the
    /// driver had accepted for it goes with it. A running message for which
    /// an explicit stop or restart recorded its interrupt is ended by the
    /// handshake, never resumed. Returns whether the record was taken.
    pub(super) fn set_aside(&mut self, record: &MessageRecord) -> bool {
        if matches!(record.state, MessageState::Running | MessageState::Paused)
            && record.action.starts_turn()
            && self.noel.set_aside.is_none()
        {
            let paused = record.state == MessageState::Paused;
            let stopped = pause::explicit_stop_recorded(&self.dir, &record.id);
            log(format!(
                "message {} was {} when the driver stopped; noel's journal decides it at startup",
                record.id,
                state_label(record)
            ));
            self.noel.set_aside = Some(SetAside {
                message_id: record.id.clone(),
                turn_id: record.turn_id.clone(),
                resumed: record.native_resumed,
                paused,
                stopped,
                interrupts: Vec::new(),
                deadline: tokio::time::Instant::now() + RESUME_DEADLINE,
                cause: if paused { PAUSED } else { RESTARTED }.into(),
                tail: RESTARTED_TAIL,
            });
            return true;
        }
        match self.noel.set_aside.as_mut() {
            Some(aside)
                if record.action == MessageAction::Interrupt
                    && matches!(record.state, MessageState::Accepted | MessageState::Running)
                    && record.expected_active_message_id.as_deref()
                        == Some(aside.message_id.as_str()) =>
            {
                aside.interrupts.push(record.id.clone());
                true
            }
            _ => false,
        }
    }

    /// Decides the set-aside message by noel's last run in `state` (see
    /// [`resolve`]). A refusal ends it unknown and startup goes on. A command
    /// noel never answers leaves it set aside, and the failed startup ends it
    /// unknown.
    async fn decide_set_aside(&mut self, peer: &mut Peer, state: &Value) -> anyhow::Result<()> {
        let Some(aside) = self.noel.set_aside.clone() else {
            return Ok(());
        };
        let last = last_run(state);
        let resolution = resolve(&aside, last.as_ref(), self.state.capabilities.resume);
        match resolution {
            Resolution::Resume { run, saved_reply } => {
                self.resume_set_aside(peer, &aside, run, saved_reply, last.as_ref())
                    .await
            }
            Resolution::Abort { run } => {
                match call(
                    peer,
                    "abort",
                    json!({"expectedRunId": run}),
                    self.handshake_deadline(),
                )
                .await
                {
                    Ok(_) => {
                        log(format!(
                            "aborted noel run {run}: message {} has an accepted interrupt",
                            aside.message_id
                        ));
                        self.settle_set_aside(run, TurnStatus::Interrupted, None, None)
                            .await
                    }
                    Err(error) => self.refused(error).await,
                }
            }
            Resolution::Ended { run, end } => {
                log(format!(
                    "noel's run {run} for message {} ended as {} while the driver was down",
                    aside.message_id,
                    end.name()
                ));
                match end {
                    // A completed run's last saved reply is its own. noel
                    // never saves a failed or aborted run's reply, so the
                    // saved one belongs to an earlier run and is not read.
                    RunEnd::Completed => {
                        let reply = match call(
                            peer,
                            "get_last_assistant_text",
                            json!({}),
                            self.handshake_deadline(),
                        )
                        .await
                        {
                            Ok(data) => data.get("text").and_then(Value::as_str).map(str::to_owned),
                            Err(error) => return self.refused(error).await,
                        };
                        self.settle_set_aside(run, TurnStatus::Completed, reply, None)
                            .await
                    }
                    RunEnd::Failed => {
                        self.settle_set_aside(
                            run,
                            TurnStatus::Failed,
                            None,
                            Some(MISSED_FAILURE.into()),
                        )
                        .await
                    }
                    RunEnd::Aborted => {
                        self.settle_set_aside(run, TurnStatus::Interrupted, None, None)
                            .await
                    }
                }
            }
            Resolution::Unknown { abort } => {
                if let Some(run) = abort {
                    // Never resumed later: no message owns it now.
                    match call(
                        peer,
                        "abort",
                        json!({"expectedRunId": run}),
                        self.handshake_deadline(),
                    )
                    .await
                    {
                        Ok(_) => log(format!("aborted interrupted noel run {run}")),
                        Err(error) if error.is::<Refused>() => log(format!("{error:#}")),
                        Err(error) => return Err(error),
                    }
                }
                self.end_set_aside_unknown(None).await;
                Ok(())
            }
        }
    }

    /// noel refused a recovery command: the set-aside message ends unknown
    /// and startup goes on. Any other failure fails the handshake.
    async fn refused(&mut self, error: anyhow::Error) -> anyhow::Result<()> {
        if !error.is::<Refused>() {
            return Err(error);
        }
        self.end_set_aside_unknown(Some(&format!("{error:#}")))
            .await;
        Ok(())
    }

    /// Continues the set-aside message's run under the same run ID; its
    /// normal settlement ends it.
    async fn resume_set_aside(
        &mut self,
        peer: &mut Peer,
        aside: &SetAside,
        run: String,
        saved_reply: bool,
        last: Option<&LastRun>,
    ) -> anyhow::Result<()> {
        // Resuming a run that stopped after its last reply was saved only
        // completes it, reporting no reply: that saved reply is its answer.
        let mut texts = Vec::new();
        if saved_reply {
            match call(
                peer,
                "get_last_assistant_text",
                json!({}),
                self.handshake_deadline(),
            )
            .await
            {
                Ok(data) => texts.extend(
                    data.get("text")
                        .and_then(Value::as_str)
                        .filter(|text| !text.is_empty())
                        .map(str::to_owned),
                ),
                Err(error) => return self.refused(error).await,
            }
        }
        // Counted before resume_run is sent, so a driver that dies before
        // the run settles finds the resume counted. A paused message runs
        // again in the same write, uncounted: its environment's takedown was
        // no crash, and a driver that dies after this finds it running.
        let record = update_message(&self.dir, &aside.message_id, |r| {
            if !r.resume() {
                r.native_resumed = r.native_resumed.saturating_add(1);
            }
            r.turn_id = Some(run.clone());
            r.native_acknowledged = true;
        })?;
        let after_pause = record.native_resumed == aside.resumed;
        if let Err(error) = call(
            peer,
            "resume_run",
            json!({"expectedRunId": run}),
            self.handshake_deadline(),
        )
        .await
        {
            return self.refused(error).await;
        }
        self.noel.set_aside = None;
        let phase = match last.and_then(|last| last.phase.as_deref()) {
            Some("tools") => format!(
                "; cut off during tool calls: {}",
                last.map(|last| last.pending.join(", ")).unwrap_or_default()
            ),
            Some("model") => "; its cut-off model request is sent again".into(),
            _ => "; its last reply was saved".into(),
        };
        if after_pause {
            log(format!(
                "message {} resumed by noel after its environment stopped: run {run}{phase}",
                record.id
            ));
        } else {
            log(format!(
                "message {} resumed by noel: run {run}, resume {} of {MAX_RESUMES}{phase}",
                record.id, record.native_resumed
            ));
        }
        self.active = Some(ActiveTurn {
            message_id: record.id.clone(),
            text: turn_text(&record),
            turn_id: Some(run.clone()),
            texts,
            steers: Vec::new(),
            interrupts: Vec::new(),
            usage: None,
            acknowledged: true,
            failure: None,
        });
        self.state.phase = DriverPhase::Busy;
        self.state.active_message_id = Some(record.id);
        self.state.current_turn_id = Some(run);
        self.persist_state()
    }

    /// Ends the set-aside message as its run ended, through the settlement
    /// the driver missed; its accepted interrupts complete with it.
    async fn settle_set_aside(
        &mut self,
        run: String,
        status: TurnStatus,
        result: Option<String>,
        error: Option<String>,
    ) -> anyhow::Result<()> {
        let Some(aside) = self.noel.set_aside.take() else {
            return Ok(());
        };
        self.active = Some(ActiveTurn {
            message_id: aside.message_id,
            text: String::new(),
            turn_id: Some(run),
            texts: Vec::new(),
            steers: Vec::new(),
            interrupts: aside.interrupts,
            usage: None,
            acknowledged: true,
            failure: None,
        });
        self.finish_turn(status, result, error, None).await
    }

    /// The set-aside message, and the interrupts accepted for it, end
    /// unknown, with `detail` saying why noel did not decide it. Its parent
    /// hears once.
    async fn end_set_aside_unknown(&mut self, detail: Option<&str>) {
        let Some(aside) = self.noel.set_aside.take() else {
            return;
        };
        let error = match detail {
            Some(detail) => format!("{}; {detail}; {}", aside.cause, aside.tail),
            None => format!("{}; {}", aside.cause, aside.tail),
        };
        for id in &aside.interrupts {
            if let Err(error) = update_message(&self.dir, id, |r| {
                r.fail(MessageState::Unknown, error.clone());
            }) {
                log(format!(
                    "could not record message {id} as unknown: {error:#}"
                ));
            }
        }
        match update_message(&self.dir, &aside.message_id, |r| {
            r.fail(MessageState::Unknown, error.clone());
        }) {
            Ok(record) => {
                log(format!("message {} unknown: {error}", record.id));
                self.notify_parent(&record).await;
            }
            Err(error) => log(format!(
                "could not record message {} as unknown: {error:#}",
                aside.message_id
            )),
        }
    }

    /// `lose_peer` and a failed startup: a message still set aside ends
    /// unknown, so none waits beyond its handshake.
    pub(super) async fn set_aside_unknown(&mut self, detail: &str) {
        self.end_set_aside_unknown(Some(detail)).await;
    }

    /// noel's output ended while a turn was active. If noel can resume runs,
    /// exited on its own, not by a signal that stops it, and was not
    /// restarted for this message before, the turn stays running: noel is
    /// started again and the startup handshake decides it. A signal that
    /// stops noel is the caller's to answer, as a stop of the driver is.
    /// Otherwise the caller loses the peer as before.
    pub(super) async fn respawn_noel(&mut self, peer: &mut Peer, reason: &str) -> Respawn {
        let Some(message_id) = self.active.as_ref().map(|active| active.message_id.clone()) else {
            return Respawn::No;
        };
        if !self.state.capabilities.resume || self.stopping {
            return Respawn::No;
        }
        // Waiting does not close noel's input, which would itself end it.
        let status = match tokio::time::timeout(STOP_GRACE, peer.child.wait()).await {
            Ok(Ok(status)) if stopped_by_signal(status) => return Respawn::Signalled,
            Ok(Ok(status)) => status,
            _ => return Respawn::No,
        };
        if self.noel.respawned_for.as_deref() == Some(message_id.as_str()) {
            return Respawn::No;
        }
        let resumed = match load_message(&self.dir, &message_id) {
            Ok(record) if record.state == MessageState::Running => record.native_resumed,
            _ => return Respawn::No,
        };
        let Some(active) = self.active.take() else {
            return Respawn::No;
        };
        self.noel.respawned_for = Some(message_id.clone());
        let cause = format!("{reason} (native agent {status})");
        // A steer the exited noel was sent is never replayed: the restarted
        // noel's queue is cleared before anything resumes.
        let mut steers = active.steers;
        steers.extend(
            self.pending
                .drain()
                .filter_map(|(_, pending)| match pending {
                    Pending::Steer(id) => Some(id),
                    Pending::TurnStart(_) | Pending::Interrupt(_) => None,
                }),
        );
        for id in steers {
            if let Err(error) = update_message(&self.dir, &id, |r| {
                r.fail(
                    MessageState::Unknown,
                    format!("{cause}; the steer outcome is unknown and is not replayed"),
                );
            }) {
                log(format!(
                    "could not record message {id} as unknown: {error:#}"
                ));
            }
        }
        self.noel.set_aside = Some(SetAside {
            message_id: message_id.clone(),
            turn_id: active.turn_id,
            resumed,
            paused: false,
            stopped: false,
            interrupts: active.interrupts,
            deadline: tokio::time::Instant::now() + RESUME_DEADLINE,
            cause: cause.clone(),
            tail: LOST_TAIL,
        });
        // The run stays the active one on disk while noel restarts, so a
        // stop or a takedown in the meantime still finds it.
        self.state.phase = DriverPhase::Starting;
        self.state.active_message_id = Some(message_id.clone());
        self.state.current_turn_id = None;
        if let Err(error) = self.persist_state() {
            log(format!("could not persist driver state: {error:#}"));
        }
        log(format!(
            "noel exited during message {message_id} ({cause}); starting it again once to recover the run"
        ));
        match self.spawn_peer() {
            Ok(next) => *peer = next,
            Err(error) => {
                self.set_aside_unknown(&format!("noel could not be started again: {error:#}"))
                    .await;
                self.state.active_message_id = None;
                return Respawn::No;
            }
        }
        if let Err(error) = self.initialize_noel(peer).await {
            self.set_aside_unknown(&format!(
                "the restarted noel did not finish its startup handshake: {error:#}"
            ))
            .await;
            self.state.active_message_id = None;
            return Respawn::No;
        }
        if self.active.is_none() {
            self.state.phase = DriverPhase::Idle;
            self.state.active_message_id = None;
        }
        if let Err(error) = self.persist_state() {
            log(format!("could not persist driver state: {error:#}"));
        }
        Respawn::Started
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

    /// A message its environment's takedown pauses, and its resume.
    mod takedown;

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
        harness_for(AgentKind::Noel)
    }

    /// An `agent` driver with private records in a temporary guest root and
    /// no peer.
    fn harness_for(agent: AgentKind) -> Harness {
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
        let created_at = now();
        let config = AgentConfig {
            version: 1,
            driver_id: driver_id.clone(),
            environment_id: environment.id().into(),
            agent,
            program: PathBuf::from("/usr/local/bin/noel"),
            program_fallback: None,
            model: "faux/echo".into(),
            effort: None,
            working_dir: "/workspace".into(),
            name: String::new(),
            parent: None,
            initial_message_id: None,
            created_at: created_at.clone(),
        };
        let binding = AgentBinding {
            driver_id,
            session_id: "session".into(),
            bound_at: created_at,
        };
        Harness {
            _temporary: temporary,
            driver: driver(environment, dir, config, binding),
        }
    }

    /// A new driver process for the conversation: what it knows of the last
    /// one is on disk.
    fn driver(
        environment: DriverEnvironment,
        dir: PathBuf,
        config: AgentConfig,
        binding: AgentBinding,
    ) -> Driver {
        let started_at = now();
        let agent = config.agent;
        Driver {
            #[cfg(target_os = "linux")]
            platform: None,
            state: DriverState {
                version: 1,
                driver_id: config.driver_id.clone(),
                agent,
                phase: DriverPhase::Idle,
                native_thread_id: Some(SESSION.into()),
                native_thread_established: true,
                current_turn_id: None,
                active_message_id: None,
                queued: 0,
                capabilities: AgentCapabilities {
                    steer: true,
                    interrupt: true,
                    resume: agent == AgentKind::Noel,
                    note: String::new(),
                },
                policy: NOEL_POLICY.into(),
                last_error: None,
                started_at: started_at.clone(),
                updated_at: started_at.clone(),
            },
            config,
            environment,
            dir,
            binding,
            started_at,
            queue: VecDeque::new(),
            active: None,
            pending: HashMap::new(),
            control_pending: HashMap::new(),
            settled: HashSet::new(),
            stopping: false,
            noel: Recovery::default(),
        }
    }

    impl Harness {
        /// The driver crashes and a new one starts on the same records.
        fn restart(&mut self) {
            let Driver {
                environment,
                dir,
                config,
                binding,
                ..
            } = &self.driver;
            self.driver = driver(
                environment.clone(),
                dir.clone(),
                config.clone(),
                binding.clone(),
            );
        }

        /// A parent conversation in the same environment, which hears of
        /// this one's finished messages. Returns its directory.
        fn with_parent(&mut self) -> PathBuf {
            let parent = uuid::Uuid::new_v4().to_string();
            let dir = agents_root(&self.driver.environment).join(&parent);
            for path in [&dir, &dir.join("messages")] {
                private_directory(path).unwrap();
            }
            let session = format!("session-{}", uuid::Uuid::new_v4());
            write_private_json(
                &dir.join("binding.json"),
                &AgentBinding {
                    driver_id: parent.clone(),
                    session_id: session.clone(),
                    bound_at: now(),
                },
            )
            .unwrap();
            self.driver.config.parent = Some(ParentLink {
                session_id: session,
                driver_id: parent,
            });
            dir
        }

        /// How often the parent in `parent` heard of message `source`.
        fn heard(&self, parent: &Path, source: &str) -> usize {
            list_messages(parent)
                .unwrap()
                .iter()
                .filter(|r| {
                    r.action == MessageAction::Notification
                        && r.source.as_ref().is_some_and(|s| s.message_id == source)
                })
                .count()
        }

        /// A message that was running when the driver died: only its
        /// record remains, naming `run` once noel's prompt reply arrived.
        fn crashed(&self, action: MessageAction, text: &str, run: Option<&str>) -> MessageRecord {
            let record = self.message(action, text);
            self.update(&record.id, |r| {
                r.transition(MessageState::Accepted);
                r.transition(MessageState::Running);
                r.turn_id = run.map(str::to_owned);
                r.native_acknowledged = run.is_some();
            });
            self.load(&record.id)
        }

        /// An interrupt of `target` the driver had accepted and sent.
        fn interrupting(&self, target: &MessageRecord) -> MessageRecord {
            let interrupt = self.message(MessageAction::Interrupt, "");
            self.update(&interrupt.id, |r| {
                r.expected_active_message_id = Some(target.id.clone());
                r.expected_turn_id = target.turn_id.clone();
                r.transition(MessageState::Accepted);
                r.transition(MessageState::Running);
            });
            self.load(&interrupt.id)
        }

        /// Feeds noel's records to the driver until its active turn ends.
        async fn settle(&mut self, peer: &mut Peer) {
            while self.driver.active.is_some() {
                let line = next_line(peer).await;
                self.driver.on_noel(peer, line).await.unwrap();
            }
        }

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
        let error = call(&mut peer, "get_state", json!({}), soon())
            .await
            .unwrap_err();
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
        let data = call(&mut peer, "get_state", json!({}), soon())
            .await
            .unwrap();
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

    fn soon() -> tokio::time::Instant {
        tokio::time::Instant::now() + Duration::from_secs(10)
    }

    /// noel `ef09c03f`'s `get_state` for faux/echo, with `lastRun` if given.
    fn resumable_state(last: Option<Value>) -> Value {
        let mut state = state();
        state["rpcExtensions"] = json!(["run-id", "expected-run-id", "request-id", "resume-run"]);
        if let Some(last) = last {
            state["lastRun"] = last;
        }
        state
    }

    /// `lastRun` for run `RUN`, started by `request`.
    fn last(request: &str, status: &str, phase: Option<&str>) -> Value {
        let mut last = json!({"runId": RUN, "requestId": request, "status": status});
        if let Some(phase) = phase {
            last["phase"] = json!(phase);
        }
        last
    }

    fn reply(id: u64, command: &str, data: Option<Value>) -> Value {
        let mut reply = json!({"id": id, "type": "response", "command": command, "success": true});
        if let Some(data) = data {
            reply["data"] = data;
        }
        reply
    }

    fn refusal(id: u64, command: &str, error: &str) -> Value {
        json!({"id": id, "type": "response", "command": command, "success": false, "error": error})
    }

    /// `clear_queue` with nothing queued, as noel answers it.
    fn cleared(id: u64) -> Step {
        step(vec![
            json!({"type": "queue_update", "steering": [], "followUp": []}),
            reply(
                id,
                "clear_queue",
                Some(json!({"steering": [], "followUp": []})),
            ),
        ])
    }

    /// What noel does for one command it reads: runs `run`, then answers
    /// with `lines`.
    struct Step {
        run: String,
        lines: Vec<Value>,
    }

    fn step(lines: Vec<Value>) -> Step {
        Step {
            run: String::new(),
            lines,
        }
    }

    /// A noel that takes `steps` in order, one per command it reads, and
    /// appends each command to `trace` first; it then appends whatever else
    /// it is sent, answering nothing.
    fn noel_peer(trace: &Path, steps: Vec<Step>) -> Peer {
        let trace = trace.display().to_string();
        assert!(!trace.contains('\''));
        let mut script = String::new();
        for Step { run, lines } in steps {
            script.push_str(&format!(
                "IFS= read -r line; printf '%s\\n' \"$line\" >> '{trace}';"
            ));
            if !run.is_empty() {
                script.push_str(&format!(" {run};"));
            }
            for line in lines {
                let line = line.to_string();
                assert!(!line.contains('\''));
                script.push_str(&format!(" printf '%s\\n' '{line}';"));
            }
            script.push('\n');
        }
        // Its output stays open: it never answers again, nor ends.
        script.push_str(&format!(
            "while IFS= read -r line; do printf '%s\\n' \"$line\" >> '{trace}'; done\n"
        ));
        script_peer(&script)
    }

    /// The commands a `noel_peer` was sent.
    fn sent(trace: &Path) -> Vec<Value> {
        fs::read_to_string(trace)
            .unwrap_or_default()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect()
    }

    fn kinds(trace: &Path) -> Vec<String> {
        sent(trace)
            .iter()
            .map(|command| command["type"].as_str().unwrap().to_owned())
            .collect()
    }

    /// The run's records after `resume_run`, as noel sends them for a
    /// cut-off model request.
    fn resumed_run(text: &str) -> Vec<Value> {
        vec![
            json!({"type": "agent_start", "runId": RUN}),
            json!({"type": "turn_start"}),
            assistant(text, "stop", json!({})),
            json!({"type": "agent_end", "messages": []}),
            json!({"type": "agent_settled", "aborted": false, "runId": RUN}),
        ]
    }

    fn started() -> Option<Value> {
        Some(json!({"disposition": "started", "runId": RUN}))
    }

    fn aside(message: &str, run: Option<&str>, resumed: u32, interrupted: bool) -> SetAside {
        SetAside {
            message_id: message.into(),
            turn_id: run.map(str::to_owned),
            resumed,
            paused: false,
            stopped: false,
            interrupts: if interrupted {
                vec!["interrupt".into()]
            } else {
                Vec::new()
            },
            deadline: soon(),
            cause: RESTARTED.into(),
            tail: RESTARTED_TAIL,
        }
    }

    fn run_of(request: Option<&str>, status: &str, phase: Option<&str>) -> LastRun {
        LastRun {
            run_id: RUN.into(),
            request_id: request.map(str::to_owned),
            status: status.into(),
            phase: phase.map(str::to_owned),
            pending: Vec::new(),
        }
    }

    /// Exactly what `recover()` writes for Codex and Claude.
    const UNKNOWN: &str =
        "the driver restarted while this was in flight; outcome unknown; not replayed";

    #[test]
    fn recovery_follows_the_table_by_noels_last_run() {
        const M: &str = "message";
        let resume = |saved_reply| Resolution::Resume {
            run: RUN.into(),
            saved_reply,
        };
        let unknown = |abort: bool| Resolution::Unknown {
            abort: abort.then(|| RUN.to_owned()),
        };
        let decide = |aside: &SetAside, last: Option<&LastRun>| resolve(aside, last, true);
        let model = |request: Option<&str>| run_of(request, "interrupted", Some("model"));

        // Bound, running or interrupted, no interrupt, fewer than 3 resumes.
        assert_eq!(
            decide(&aside(M, Some(RUN), 0, false), Some(&model(Some(M)))),
            resume(false)
        );
        assert_eq!(
            decide(
                &aside(M, None, 2, false),
                Some(&run_of(Some(M), "interrupted", Some("tools")))
            ),
            resume(false)
        );
        assert_eq!(
            decide(
                &aside(M, None, 0, false),
                Some(&run_of(Some(M), "running", None))
            ),
            resume(false)
        );
        // Stopped after its last reply was saved: resuming only completes it.
        assert_eq!(
            decide(
                &aside(M, None, 0, false),
                Some(&run_of(Some(M), "interrupted", None))
            ),
            resume(true)
        );
        // An interrupt accepted before the crash ends the run instead.
        assert_eq!(
            decide(&aside(M, Some(RUN), 0, true), Some(&model(Some(M)))),
            Resolution::Abort { run: RUN.into() }
        );
        // Ended while the driver was down: the settlement was missed.
        for (status, end) in [
            ("completed", RunEnd::Completed),
            ("failed", RunEnd::Failed),
            ("aborted", RunEnd::Aborted),
        ] {
            for interrupted in [false, true] {
                assert_eq!(
                    decide(
                        &aside(M, Some(RUN), 3, interrupted),
                        Some(&run_of(Some(M), status, None))
                    ),
                    Resolution::Ended {
                        run: RUN.into(),
                        end
                    }
                );
            }
        }
        // Resumed three times already: the run is aborted, never resumed.
        assert_eq!(
            decide(&aside(M, Some(RUN), 3, false), Some(&model(Some(M)))),
            unknown(true)
        );
        assert_eq!(
            decide(
                &aside(M, Some(RUN), 3, false),
                Some(&run_of(Some(M), "running", None))
            ),
            unknown(false)
        );
        // Another request's run, a run without a request, none, or a run
        // other than the one Codewire recorded. An interrupted one is aborted.
        assert_eq!(
            decide(&aside(M, None, 0, false), Some(&model(Some("other")))),
            unknown(true)
        );
        assert_eq!(
            decide(
                &aside(M, None, 0, false),
                Some(&run_of(Some("other"), "completed", None))
            ),
            unknown(false)
        );
        assert_eq!(
            decide(&aside(M, None, 0, false), Some(&model(None))),
            unknown(true)
        );
        assert_eq!(
            decide(
                &aside(M, Some("another-run"), 0, false),
                Some(&model(Some(M)))
            ),
            unknown(true)
        );
        assert_eq!(decide(&aside(M, None, 0, false), None), unknown(false));
        // A noel without both resume extensions.
        assert_eq!(
            resolve(&aside(M, Some(RUN), 0, false), Some(&model(Some(M))), false),
            unknown(false)
        );
    }

    #[test]
    fn last_run_reads_noels_get_state() {
        // As noel `ef09c03f` reports a run a kill cut off during its bash call.
        let state = resumable_state(Some(
            json!({"runId": RUN, "requestId": "m-2", "status": "interrupted",
            "phase": "tools", "pendingTools": [{"id": "call_1_1", "name": "bash", "replaySafe": false},
                                               {"id": "call_1_2", "name": "read", "replaySafe": true}]}),
        ));
        assert_eq!(
            last_run(&state),
            Some(LastRun {
                run_id: RUN.into(),
                request_id: Some("m-2".into()),
                status: "interrupted".into(),
                phase: Some("tools".into()),
                pending: vec![
                    "bash is reported interrupted, not run again".into(),
                    "read runs again".into()
                ],
            })
        );
        let completed = last_run(&resumable_state(Some(
            json!({"runId": RUN, "status": "completed"}),
        )))
        .unwrap();
        assert_eq!((completed.request_id, completed.phase), (None, None));
        assert_eq!(last_run(&resumable_state(None)), None);
        assert_eq!(
            last_run(&resumable_state(Some(json!({"status": "completed"})))),
            None
        );
    }

    #[test]
    fn only_a_stop_signal_keeps_noel_from_being_started_again() {
        use std::os::unix::process::ExitStatusExt as _;
        let exited = |code: i32| std::process::ExitStatus::from_raw(code << 8);
        let signalled = std::process::ExitStatus::from_raw;
        for stopped in [
            exited(143),
            exited(129),
            exited(130),
            signalled(libc::SIGTERM),
            signalled(libc::SIGINT),
        ] {
            assert!(stopped_by_signal(stopped), "{stopped}");
        }
        for died in [
            signalled(libc::SIGKILL),
            signalled(libc::SIGSEGV),
            exited(101),
            exited(0),
            exited(1),
        ] {
            assert!(!stopped_by_signal(died), "{died}");
        }
    }

    #[tokio::test]
    async fn a_crashed_run_resumes_counted_before_resume_run_is_sent_and_its_parent_hears_once() {
        let mut h = harness();
        let parent = h.with_parent();
        let main = h.crashed(MessageAction::Message, "task", Some(RUN));
        // A steer noel acknowledged before the crash is never replayed.
        let steer = h.crashed(MessageAction::Steer, "be brief", Some(RUN));
        h.driver.recover().await.unwrap();
        assert_eq!(h.load(&main.id).state, MessageState::Running);
        let unreplayed = h.load(&steer.id);
        assert_eq!(
            (unreplayed.state, unreplayed.error.as_deref()),
            (MessageState::Unknown, Some(UNKNOWN))
        );
        assert_eq!(h.heard(&parent, &main.id), 0);

        let trace = h._temporary.path().join("sent.jsonl");
        let snapshot = h
            ._temporary
            .path()
            .join("record-when-resume-run-arrived.json");
        let record = message_path(&h.driver.dir, &main.id);
        let mut resume = vec![reply(3, "resume_run", started())];
        resume.extend(resumed_run("[faux/echo] task"));
        let mut peer = noel_peer(
            &trace,
            vec![
                step(vec![reply(
                    1,
                    "get_state",
                    Some(resumable_state(Some(last(
                        &main.id,
                        "interrupted",
                        Some("model"),
                    )))),
                )]),
                // noel saved the steer before the crash; clearing it comes first.
                step(vec![
                    json!({"type": "queue_update", "steering": [], "followUp": []}),
                    reply(
                        2,
                        "clear_queue",
                        Some(json!({"steering": ["be brief"], "followUp": []})),
                    ),
                ]),
                Step {
                    run: format!("cp '{}' '{}'", record.display(), snapshot.display()),
                    lines: resume,
                },
            ],
        );
        h.driver.initialize_noel(&mut peer).await.unwrap();
        assert_eq!(kinds(&trace), ["get_state", "clear_queue", "resume_run"]);
        assert_eq!(
            sent(&trace)[2],
            json!({"id": 3, "type": "resume_run", "expectedRunId": RUN})
        );
        // Counted on disk before noel read resume_run.
        let before: MessageRecord = read_record(&snapshot).unwrap();
        assert_eq!(
            (before.state, before.native_resumed),
            (MessageState::Running, 1)
        );
        assert!(h.driver.noel.set_aside.is_none());
        assert!(h.driver.state.capabilities.resume);
        assert_eq!(h.driver.state.phase, DriverPhase::Busy);
        assert_eq!(
            h.driver.state.active_message_id.as_deref(),
            Some(main.id.as_str())
        );
        assert_eq!(h.driver.state.current_turn_id.as_deref(), Some(RUN));
        assert_eq!(
            h.heard(&parent, &main.id),
            0,
            "the parent hears only of the final state"
        );

        h.settle(&mut peer).await;
        let resumed = h.load(&main.id);
        assert_eq!(resumed.state, MessageState::Completed);
        assert_eq!(resumed.result.as_deref(), Some("[faux/echo] task"));
        assert_eq!(
            (resumed.native_resumed, resumed.turn_id.as_deref()),
            (1, Some(RUN))
        );
        assert_eq!(resumed_note(&resumed), " (resumed by noel)");
        assert_eq!(h.driver.state.phase, DriverPhase::Idle);
        assert_eq!(h.heard(&parent, &main.id), 1);
    }

    #[tokio::test]
    async fn an_interrupt_accepted_before_the_crash_aborts_the_run_instead_of_resuming_it() {
        let mut h = harness();
        let parent = h.with_parent();
        let main = h.crashed(MessageAction::Message, "task", Some(RUN));
        let interrupt = h.interrupting(&main);
        h.driver.recover().await.unwrap();
        assert_eq!(
            h.load(&interrupt.id).state,
            MessageState::Running,
            "it goes with its message"
        );
        let trace = h._temporary.path().join("sent.jsonl");
        let mut peer = noel_peer(
            &trace,
            vec![
                step(vec![reply(
                    1,
                    "get_state",
                    Some(resumable_state(Some(last(
                        &main.id,
                        "interrupted",
                        Some("model"),
                    )))),
                )]),
                cleared(2),
                step(vec![reply(3, "abort", None)]),
            ],
        );
        h.driver.initialize_noel(&mut peer).await.unwrap();
        assert_eq!(
            sent(&trace)[2],
            json!({"id": 3, "type": "abort", "expectedRunId": RUN})
        );
        let ended = h.load(&main.id);
        assert_eq!(
            (ended.state, ended.native_resumed),
            (MessageState::Interrupted, 0)
        );
        let interrupt = h.load(&interrupt.id);
        assert_eq!(interrupt.state, MessageState::Completed);
        assert_eq!(
            interrupt.result,
            Some(format!("turn {RUN} ended as interrupted"))
        );
        assert!(h.driver.active.is_none());
        assert_eq!(h.driver.state.phase, DriverPhase::Idle);
        assert_eq!(h.heard(&parent, &main.id), 1);
    }

    #[tokio::test]
    async fn a_missed_settlement_ends_the_message_as_noel_ended_its_run() {
        for (status, state, result, error) in [
            (
                "completed",
                MessageState::Completed,
                Some("[faux/echo] task"),
                None,
            ),
            ("failed", MessageState::Error, None, Some(MISSED_FAILURE)),
            ("aborted", MessageState::Interrupted, None, None),
        ] {
            let mut h = harness();
            let parent = h.with_parent();
            // noel's prompt reply never reached the driver.
            let main = h.crashed(MessageAction::Message, "task", None);
            h.driver.recover().await.unwrap();
            let trace = h._temporary.path().join("sent.jsonl");
            let mut steps = vec![
                step(vec![reply(
                    1,
                    "get_state",
                    Some(resumable_state(Some(last(&main.id, status, None)))),
                )]),
                cleared(2),
            ];
            if status == "completed" {
                steps.push(step(vec![reply(
                    3,
                    "get_last_assistant_text",
                    Some(json!({"text": "[faux/echo] task"})),
                )]));
            }
            let mut peer = noel_peer(&trace, steps);
            h.driver.initialize_noel(&mut peer).await.unwrap();
            let ended = h.load(&main.id);
            assert_eq!(
                (ended.state, ended.result.as_deref(), ended.error.as_deref()),
                (state, result, error),
                "{status}"
            );
            assert_eq!(ended.turn_id.as_deref(), Some(RUN));
            assert_eq!(ended.native_resumed, 0);
            // noel saves no reply for a failed or aborted run, so the last
            // saved one is another run's and is not read.
            let read: &[&str] = if status == "completed" {
                &["get_state", "clear_queue", "get_last_assistant_text"]
            } else {
                &["get_state", "clear_queue"]
            };
            assert_eq!(kinds(&trace), read, "{status}");
            assert!(h.driver.active.is_none());
            assert_eq!(h.heard(&parent, &main.id), 1, "{status}");
        }
    }

    #[tokio::test]
    async fn anything_else_ends_the_message_unknown_exactly_as_codex_and_claude_do() {
        assert_eq!(format!("{RESTARTED}; {RESTARTED_TAIL}"), UNKNOWN);
        for case in [
            "another request's interrupted run",
            "no run",
            "a noel that cannot resume",
            "resumed three times",
        ] {
            let mut h = harness();
            let parent = h.with_parent();
            let main = h.crashed(MessageAction::Message, "task", Some(RUN));
            let mut abort = true;
            let state = match case {
                "another request's interrupted run" => resumable_state(Some(last(
                    "4f9b2c1e-0a7d-4e3b-9c5f-2d8e6a1b3c70",
                    "interrupted",
                    Some("model"),
                ))),
                "no run" => {
                    abort = false;
                    resumable_state(None)
                }
                "a noel that cannot resume" => {
                    abort = false;
                    let mut old = state();
                    old["lastRun"] = last(&main.id, "interrupted", Some("model"));
                    old
                }
                _ => {
                    h.update(&main.id, |r| r.native_resumed = MAX_RESUMES);
                    resumable_state(Some(last(&main.id, "interrupted", Some("model"))))
                }
            };
            h.driver.recover().await.unwrap();
            let trace = h._temporary.path().join("sent.jsonl");
            let mut steps = vec![step(vec![reply(1, "get_state", Some(state))]), cleared(2)];
            if abort {
                steps.push(step(vec![reply(3, "abort", None)]));
            }
            let mut peer = noel_peer(&trace, steps);
            h.driver.initialize_noel(&mut peer).await.unwrap();
            let ended = h.load(&main.id);
            assert_eq!(
                (ended.state, ended.error.as_deref()),
                (MessageState::Unknown, Some(UNKNOWN)),
                "{case}"
            );
            if abort {
                assert_eq!(
                    sent(&trace)[2],
                    json!({"id": 3, "type": "abort", "expectedRunId": RUN}),
                    "{case}"
                );
            } else {
                assert_eq!(kinds(&trace), ["get_state", "clear_queue"], "{case}");
            }
            assert_eq!(
                h.driver.state.capabilities.resume,
                case != "a noel that cannot resume"
            );
            assert!(h.driver.active.is_none() && h.driver.noel.set_aside.is_none());
            assert_eq!(h.heard(&parent, &main.id), 1, "{case}");
        }
    }

    #[tokio::test]
    async fn a_run_stopped_after_its_last_reply_was_saved_completes_with_that_reply() {
        let mut h = harness();
        let main = h.crashed(MessageAction::Message, "task", Some(RUN));
        h.driver.recover().await.unwrap();
        let trace = h._temporary.path().join("sent.jsonl");
        // Resuming it reports no reply, as noel `ef09c03f` does.
        let mut peer = noel_peer(
            &trace,
            vec![
                step(vec![reply(
                    1,
                    "get_state",
                    Some(resumable_state(Some(last(&main.id, "interrupted", None)))),
                )]),
                cleared(2),
                step(vec![reply(
                    3,
                    "get_last_assistant_text",
                    Some(json!({"text": "[faux/echo] task"})),
                )]),
                step(vec![
                    reply(4, "resume_run", started()),
                    json!({"type": "agent_start", "runId": RUN}),
                    json!({"type": "agent_end", "messages": []}),
                    json!({"type": "agent_settled", "aborted": false, "runId": RUN}),
                ]),
            ],
        );
        h.driver.initialize_noel(&mut peer).await.unwrap();
        assert_eq!(
            kinds(&trace),
            [
                "get_state",
                "clear_queue",
                "get_last_assistant_text",
                "resume_run"
            ]
        );
        h.settle(&mut peer).await;
        let resumed = h.load(&main.id);
        assert_eq!(resumed.state, MessageState::Completed);
        assert_eq!(resumed.result.as_deref(), Some("[faux/echo] task"));
        assert_eq!(resumed.native_resumed, 1);
    }

    #[tokio::test]
    async fn a_refused_resume_ends_the_message_unknown_and_startup_goes_on() {
        let mut h = harness();
        let parent = h.with_parent();
        let main = h.crashed(MessageAction::Message, "task", Some(RUN));
        h.driver.recover().await.unwrap();
        let trace = h._temporary.path().join("sent.jsonl");
        let mut peer = noel_peer(
            &trace,
            vec![
                step(vec![reply(
                    1,
                    "get_state",
                    Some(resumable_state(Some(last(
                        &main.id,
                        "interrupted",
                        Some("model"),
                    )))),
                )]),
                cleared(2),
                step(vec![refusal(
                    3,
                    "resume_run",
                    &format!("run {RUN} is not interrupted"),
                )]),
            ],
        );
        h.driver.initialize_noel(&mut peer).await.unwrap();
        let ended = h.load(&main.id);
        assert_eq!(ended.state, MessageState::Unknown);
        assert_eq!(
            ended.error,
            Some(format!(
                "{RESTARTED}; noel refused resume_run: run {RUN} is not interrupted; {RESTARTED_TAIL}"
            ))
        );
        // The attempt was counted before it was sent.
        assert_eq!(ended.native_resumed, 1);
        assert!(h.driver.active.is_none() && h.driver.noel.set_aside.is_none());
        assert_eq!(h.heard(&parent, &main.id), 1);
    }

    #[tokio::test]
    async fn a_set_aside_message_waits_no_longer_than_its_handshake() {
        // noel never answers get_state.
        let mut h = harness();
        let parent = h.with_parent();
        let main = h.crashed(MessageAction::Message, "task", Some(RUN));
        h.driver.recover().await.unwrap();
        h.driver.noel.set_aside.as_mut().unwrap().deadline =
            tokio::time::Instant::now() + Duration::from_millis(300);
        let mut peer = script_peer("while IFS= read -r line; do :; done");
        let started = Instant::now();
        let error = h.driver.initialize_noel(&mut peer).await.unwrap_err();
        assert!(started.elapsed() < Duration::from_secs(5));
        assert!(
            error
                .to_string()
                .starts_with("noel get_state did not answer within 0."),
            "{error:#}"
        );
        assert_eq!(h.load(&main.id).state, MessageState::Running);
        // The failed startup ends it unknown, and its parent hears once.
        assert!(h.driver.startup_failed(error).await.is_err());
        let ended = h.load(&main.id);
        assert_eq!(ended.state, MessageState::Unknown);
        let reason = ended.error.unwrap();
        assert!(
            reason.starts_with(&format!(
                "{RESTARTED}; noel startup failed: noel get_state did not answer"
            )),
            "{reason}"
        );
        assert!(reason.ends_with(RESTARTED_TAIL), "{reason}");
        h.driver.set_aside_unknown("again").await;
        assert_eq!(h.heard(&parent, &main.id), 1);

        // The same deadline holds after resume_run is sent and never answered.
        let mut h = harness();
        let parent = h.with_parent();
        let main = h.crashed(MessageAction::Message, "task", Some(RUN));
        h.driver.recover().await.unwrap();
        h.driver.noel.set_aside.as_mut().unwrap().deadline =
            tokio::time::Instant::now() + Duration::from_millis(500);
        let trace = h._temporary.path().join("sent.jsonl");
        let mut peer = noel_peer(
            &trace,
            vec![
                step(vec![reply(
                    1,
                    "get_state",
                    Some(resumable_state(Some(last(
                        &main.id,
                        "interrupted",
                        Some("model"),
                    )))),
                )]),
                cleared(2),
            ],
        );
        let started = Instant::now();
        let error = h.driver.initialize_noel(&mut peer).await.unwrap_err();
        assert!(started.elapsed() < Duration::from_secs(5));
        assert!(
            error
                .to_string()
                .starts_with("noel resume_run did not answer"),
            "{error:#}"
        );
        h.driver.startup_failed(error).await.unwrap_err();
        let ended = h.load(&main.id);
        assert_eq!(
            (ended.state, ended.native_resumed),
            (MessageState::Unknown, 1)
        );
        assert_eq!(h.heard(&parent, &main.id), 1);
    }

    #[tokio::test]
    async fn a_stop_during_the_handshake_ends_the_set_aside_message_unknown_once() {
        let mut h = harness();
        let parent = h.with_parent();
        let main = h.crashed(MessageAction::Message, "task", Some(RUN));
        h.driver.recover().await.unwrap();
        // The signal reached noel too.
        let mut peer = script_peer("exit 143");
        h.driver
            .lose_peer(&mut peer, "startup stopped by SIGTERM".into(), true)
            .await
            .unwrap();
        let ended = h.load(&main.id);
        assert_eq!(ended.state, MessageState::Unknown);
        assert_eq!(
            ended.error,
            Some(format!(
                "{RESTARTED}; startup stopped by SIGTERM (native agent exit status: 143); {RESTARTED_TAIL}"
            ))
        );
        assert_eq!(h.heard(&parent, &main.id), 1);
    }

    #[tokio::test]
    async fn a_driver_that_dies_after_resume_run_resumes_again_counted_and_the_parent_hears_once() {
        let mut h = harness();
        let parent = h.with_parent();
        let main = h.crashed(MessageAction::Message, "task", Some(RUN));
        let handshake = |main: &MessageRecord, id: u64, run: Vec<Value>| {
            let mut resume = vec![reply(id, "resume_run", started())];
            resume.extend(run);
            vec![
                step(vec![reply(
                    1,
                    "get_state",
                    Some(resumable_state(Some(last(
                        &main.id,
                        "interrupted",
                        Some("model"),
                    )))),
                )]),
                cleared(2),
                step(resume),
            ]
        };
        h.driver.recover().await.unwrap();
        let first = h._temporary.path().join("first.jsonl");
        // The resumed run is still going when the driver dies.
        let mut peer = noel_peer(
            &first,
            handshake(&main, 3, vec![json!({"type": "agent_start", "runId": RUN})]),
        );
        h.driver.initialize_noel(&mut peer).await.unwrap();
        assert_eq!(kinds(&first), ["get_state", "clear_queue", "resume_run"]);
        assert_eq!(h.load(&main.id).native_resumed, 1);
        drop(peer);

        // The next driver finds the resume counted and the message running;
        // nothing told the parent anything yet.
        h.restart();
        h.driver.recover().await.unwrap();
        assert_eq!(h.load(&main.id).state, MessageState::Running);
        assert_eq!(h.driver.noel.set_aside.as_ref().unwrap().resumed, 1);
        assert_eq!(h.heard(&parent, &main.id), 0);
        let second = h._temporary.path().join("second.jsonl");
        let mut peer = noel_peer(
            &second,
            handshake(&main, 3, resumed_run("[faux/echo] task")),
        );
        h.driver.initialize_noel(&mut peer).await.unwrap();
        h.settle(&mut peer).await;
        let ended = h.load(&main.id);
        assert_eq!(
            (ended.state, ended.native_resumed),
            (MessageState::Completed, 2)
        );
        assert_eq!(resumed_note(&ended), " (resumed by noel 2 times)");
        assert_eq!(h.heard(&parent, &main.id), 1);

        // A later restart repairs, never repeats, that notification.
        h.restart();
        h.driver.recover().await.unwrap();
        assert!(h.driver.noel.set_aside.is_none());
        assert_eq!(h.heard(&parent, &main.id), 1);
    }

    #[tokio::test]
    async fn noel_starts_again_only_after_dying_on_its_own_once_per_message() {
        let mut h = harness();
        let parent = h.with_parent();
        let main = h.running("task", Some(RUN));
        const CLOSED: &str = "the native agent closed its output";
        // A stop signal ended it: no restart, and the caller answers the
        // stop, even after one restart for this message.
        for restarted in [false, true] {
            h.driver.noel.respawned_for = restarted.then(|| main.id.clone());
            let mut peer = script_peer("exit 143");
            assert_eq!(
                h.driver.respawn_noel(&mut peer, CLOSED).await,
                Respawn::Signalled
            );
        }
        h.driver.noel.respawned_for = None;
        // An explicit stop's interrupt is underway: no restart.
        h.driver.stopping = true;
        let mut peer = script_peer("kill -9 $$");
        assert_eq!(h.driver.respawn_noel(&mut peer, CLOSED).await, Respawn::No);
        h.driver.stopping = false;
        // This noel cannot resume a run: no restart, as before.
        h.driver.state.capabilities.resume = false;
        assert_eq!(h.driver.respawn_noel(&mut peer, CLOSED).await, Respawn::No);
        h.driver.state.capabilities.resume = true;
        // Already restarted once for this message: no restart.
        h.driver.noel.respawned_for = Some(main.id.clone());
        assert_eq!(h.driver.respawn_noel(&mut peer, CLOSED).await, Respawn::No);
        assert!(h.driver.active.is_some() && h.driver.noel.set_aside.is_none());
        assert_eq!(h.load(&main.id).state, MessageState::Running);
        h.driver.noel.respawned_for = None;

        // Killed: noel is started again, which this guest placement refuses,
        // so the message ends unknown and its parent hears once.
        let mut peer = script_peer("kill -9 $$");
        assert_eq!(h.driver.respawn_noel(&mut peer, CLOSED).await, Respawn::No);
        assert_eq!(
            h.driver.noel.respawned_for.as_deref(),
            Some(main.id.as_str())
        );
        let ended = h.load(&main.id);
        assert_eq!(ended.state, MessageState::Unknown);
        let reason = ended.error.unwrap();
        assert!(
            reason.starts_with("the native agent closed its output (native agent signal: 9 (SIGKILL)); noel could not be started again: noel managed conversations are qualified only on trusted Linux hosts"),
            "{reason}"
        );
        assert!(reason.ends_with(LOST_TAIL), "{reason}");
        assert_eq!(h.heard(&parent, &main.id), 1);
        // The caller then loses the peer, as before; no second notification.
        assert!(
            h.driver
                .lose_peer(
                    &mut peer,
                    "the native agent closed its output".into(),
                    false
                )
                .await
                .is_err()
        );
        assert_eq!(h.driver.state.phase, DriverPhase::Failed);
        assert_eq!(h.heard(&parent, &main.id), 1);
    }

    #[tokio::test]
    async fn codex_and_claude_recovery_is_unchanged() {
        for agent in [AgentKind::Codex, AgentKind::Claude] {
            let mut h = harness_for(agent);
            let parent = h.with_parent();
            let main = h.crashed(MessageAction::Message, "task", Some(RUN));
            let steer = h.crashed(MessageAction::Steer, "be brief", Some(RUN));
            let interrupt = h.interrupting(&main);
            let queued = h.message(MessageAction::Message, "next");
            h.update(&queued.id, |r| {
                r.transition(MessageState::Accepted);
            });
            h.driver.recover().await.unwrap();
            assert!(h.driver.noel.set_aside.is_none(), "{agent:?}");
            for id in [&main.id, &steer.id, &interrupt.id] {
                let record = h.load(id);
                assert_eq!(
                    (record.state, record.error.as_deref()),
                    (MessageState::Unknown, Some(UNKNOWN)),
                    "{agent:?}"
                );
            }
            assert_eq!(
                h.driver.queue,
                std::slice::from_ref(&queued.id),
                "{agent:?}"
            );
            assert_eq!(h.heard(&parent, &main.id), 1, "{agent:?}");
            // Records and state keep their bytes: no resume count or capability.
            let record: Value =
                serde_json::from_slice(&fs::read(message_path(&h.driver.dir, &main.id)).unwrap())
                    .unwrap();
            assert!(record.get("native_resumed").is_none(), "{agent:?}");
            let state: Value =
                serde_json::from_slice(&fs::read(h.driver.dir.join("state.json")).unwrap())
                    .unwrap();
            assert!(state["capabilities"].get("resume").is_none(), "{agent:?}");
        }
    }

    #[test]
    fn the_inbox_notes_how_often_noel_resumed_a_message() {
        let mut record =
            MessageRecord::new("driver", "session", MessageAction::Message, "task".into());
        assert_eq!(resumed_note(&record), "");
        assert!(
            serde_json::to_value(&record)
                .unwrap()
                .get("native_resumed")
                .is_none()
        );
        record.native_resumed = 1;
        assert_eq!(resumed_note(&record), " (resumed by noel)");
        assert_eq!(serde_json::to_value(&record).unwrap()["native_resumed"], 1);
        record.native_resumed = 3;
        assert_eq!(resumed_note(&record), " (resumed by noel 3 times)");
        // Records and state written before this field read as before.
        let mut old = serde_json::to_value(&record).unwrap();
        old.as_object_mut().unwrap().remove("native_resumed");
        let old: MessageRecord = serde_json::from_value(old).unwrap();
        assert_eq!(old.native_resumed, 0);
        let capabilities: AgentCapabilities =
            serde_json::from_value(json!({"steer": true, "interrupt": true, "note": "n"})).unwrap();
        assert!(!capabilities.resume);
        assert_eq!(
            serde_json::to_value(&capabilities).unwrap(),
            json!({"steer": true, "interrupt": true, "note": "n"})
        );
    }
}
