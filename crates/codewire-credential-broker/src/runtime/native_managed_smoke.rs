//! Feature-only managed-agent behavior for the synthetic smoke upstream.
//!
//! The pinned guest Codex and Claude reach this fixture through the real
//! broker injection and redaction path. A request opts in only when its latest
//! user text starts with `CW_FIXTURE_`; every other request keeps the canned
//! one-turn bytes in `runtime.rs`. The marker's first line must match one
//! closed form, otherwise the request fails instead of falling back:
//!
//! - Codex `CW_FIXTURE_TOOL printf %s CW_TOOL_MARKER_<16 uppercase hex> > .cwnm-<8 lowercase hex>-tool-marker`
//! - Codex `CW_FIXTURE_CUSTODY <8 lowercase hex>`: two bounded test children,
//!   with exact births recorded in `.cwnm-<nonce>-custody.json`, then a held turn.
//! - Codex or Claude `CW_FIXTURE_HOLD <8 lowercase hex>`
//! - Codex `CW_FIXTURE_STEERABLE <8 lowercase hex>`, then `CW_FIXTURE_STEER <same nonce>`
//! - Codex `CW_FIXTURE_UPDATE_STEERABLE <8 lowercase hex>` holds across a live
//!   update. A separate `CW_FIXTURE_UPDATE_RELEASE <same nonce>` releases it;
//!   the original queued `CW_FIXTURE_UPDATE_STEER <same nonce>` consumes the
//!   scoped release evidence exactly once. Caller history cannot create it.
//!
//! Every stream reflects the injected value split across chunks, so the real
//! streaming redactor must remove it. Timers live inside the response stream:
//! a client cancellation drops them, and an uncancelled hold ends after a
//! bounded limit with distinct expiry text rather than a success marker.

use std::collections::BTreeMap;
use std::pin::Pin;
use std::sync::{Arc, Mutex, OnceLock};
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::Bytes;
use futures::{Stream, StreamExt as _, stream};
use serde_json::{Value, json};
use tokio::sync::watch;
use tokio::time::Instant;

use super::{BrokerUpstreamBody, BrokerUpstreamError};

const MARKER_PREFIX: &str = "CW_FIXTURE_";
// Verification-only, closed fixture. It starts two sleeping descendants in
// the owned VM, one detached and one double-forked. Both ignore TERM so the
// guardian must adopt and escalate; they self-exit after 240 seconds even if
// the surrounding test fails. No incoming text becomes code or a path.
const CUSTODY_TOOL_SCRIPT: &str = r#"import json, os, re, select, signal, sys, time
nonce = sys.argv[1]
if re.fullmatch("[0-9a-f]{8}", nonce) is None:
    raise SystemExit(64)
boot = open("/proc/sys/kernel/random/boot_id").read().strip()
path = ".cwnm-" + nonce + "-custody.json"
# Reserve this nonce before creating any child. Repeating the tool command
# fails before fork rather than starting an unrecorded second family.
descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
reader, writer = os.pipe()
for role in ("detached", "double_fork"):
    child = os.fork()
    if child == 0:
        os.close(descriptor)
        os.close(reader)
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        os.setsid()
        if role == "double_fork" and os.fork() != 0:
            os._exit(0)
        sink = os.open("/dev/null", os.O_RDWR)
        for descriptor in (0, 1, 2):
            os.dup2(sink, descriptor)
        if sink > 2:
            os.close(sink)
        pid = os.getpid()
        fields = open("/proc/%d/stat" % pid).read().rsplit(") ", 1)[1].split()
        record = {"role": role, "pid": pid, "start_ticks": int(fields[19])}
        os.write(writer, (json.dumps(record) + "\n").encode())
        os.close(writer)
        deadline = time.monotonic() + 240
        while time.monotonic() < deadline:
            time.sleep(1)
        os._exit(0)
os.close(writer)
data = b""
deadline = time.monotonic() + 5
while data.count(b"\n") < 2:
    remaining = deadline - time.monotonic()
    if remaining <= 0 or not select.select([reader], [], [], remaining)[0]:
        raise SystemExit(65)
    part = os.read(reader, 4096 - len(data))
    if not part or len(data) + len(part) > 4096:
        raise SystemExit(66)
    data += part
os.close(reader)
children = [json.loads(line) for line in data.splitlines()]
if len(children) != 2 or {child["role"] for child in children} != {"detached", "double_fork"}:
    raise SystemExit(67)
with os.fdopen(descriptor, "w") as output:
    json.dump({"version": 1, "nonce": nonce, "boot_id": boot, "children": children}, output)
    output.flush()
    os.fsync(output.fileno())
"#;
/// Codex may record a context update as a user message after the prompt.
const CODEX_CONTEXT_TAG: &str = "<environment_context>";
const CLAUDE_REMINDER_TAG: &str = "<system-reminder>";
/// A held stream stays open at least this long unless the client cancels it.
const HOLD_LIMIT: Duration = Duration::from_secs(120);
/// A steerable stream completes on its own after the harness can steer it.
const STEERABLE_DELAY: Duration = Duration::from_secs(12);
const UPDATE_HOLD_LIMIT: Duration = Duration::from_secs(600);
const MAXIMUM_UPDATE_REGISTRATIONS: usize = 16;
const CLAUDE_KEEPALIVE: Duration = Duration::from_secs(15);
/// The streaming redactor withholds a tail as long as its longest pattern;
/// an ignored SSE comment after timed events lets them reach the client.
const FLUSH_PADDING_BYTES: usize = 1024;
/// Function and local-shell arguments that carry the command as argv.
const SHELL_ARGV: [&str; 2] = ["bash", "-lc"];
const TOOL_ITEM_TYPES: [&str; 5] = [
    "function_call",
    "function_call_output",
    "local_shell_call",
    "custom_tool_call",
    "custom_tool_call_output",
];

#[derive(Debug, PartialEq, Eq)]
enum Marker {
    Tool { command: String, call_id: String },
    Custody(String),
    Hold(String),
    Steerable(String),
    Steer(String),
    UpdateSteerable(String),
    UpdateSteer(String),
    UpdateRelease(String),
}

/// Marker-selected Codex Responses stream, or `None` for the canned reply.
pub(super) fn codex(
    body: &[u8],
    reflection: &str,
) -> Result<Option<BrokerUpstreamBody>, BrokerUpstreamError> {
    let Ok(payload) = serde_json::from_slice::<Value>(body) else {
        return Ok(None);
    };
    let (earlier, text, after): (&[Value], &str, &[Value]) = match payload.get("input") {
        Some(Value::String(text)) => (&[], text.as_str(), &[]),
        Some(Value::Array(items)) => match latest_codex_user(items) {
            Some((index, text)) => (&items[..index], text, &items[index + 1..]),
            None => return Ok(None),
        },
        _ => return Ok(None),
    };
    let Some(marker) = marker(text)? else {
        return Ok(None);
    };
    let planned =
        match marker {
            Marker::Tool { command, call_id } => {
                codex_tool(&payload, after, &command, &call_id, reflection)?
            }
            Marker::Custody(nonce) => {
                let command = custody_command(&nonce);
                let call_id = format!("call_cw_custody_{nonce}");
                // The returning history must contain our exact fixed command,
                // rather than merely reusing its deterministic call ID.
                for item in after {
                    if matches!(
                        item.get("type").and_then(Value::as_str),
                        Some("function_call" | "local_shell_call")
                    ) && !ShellTool::PREFERENCE.into_iter().any(|tool| {
                        tool.matches_call(item, &command, &call_id)
                            && payload.get("tools").and_then(Value::as_array).is_some_and(
                                |offered| offered.iter().any(|offered| tool.accepts(offered)),
                            )
                    }) {
                        return Err(BrokerUpstreamError::Protocol);
                    }
                }
                let mut planned = codex_tool(&payload, after, &command, &call_id, reflection)?;
                // codex_tool has already validated exactly one matching call and
                // output. Never issue the descendant fixture a second time.
                if after.iter().any(|item| {
                    item.get("type").and_then(Value::as_str) == Some("function_call_output")
                }) {
                    planned.opening = codex_created("custody_hold", reflection);
                    planned.later = Later::Hold {
                        keepalive: None,
                        expiry: codex_reply("custody_hold", &format!("CW_CUSTODY_EXPIRED {nonce}")),
                    };
                }
                planned
            }
            Marker::Hold(nonce) => Planned {
                opening: codex_created("hold", reflection),
                later: Later::Hold {
                    keepalive: None,
                    expiry: codex_reply("hold", &format!("CW_HOLD_EXPIRED {nonce}")),
                },
            },
            Marker::Steerable(nonce) => Planned {
                opening: codex_created("steerable", reflection),
                later: Later::After(
                    STEERABLE_DELAY,
                    codex_reply("steerable", &format!("CW_STEERABLE_WAITED {nonce}")),
                ),
            },
            Marker::Steer(nonce) => {
                let steerable = format!("CW_FIXTURE_STEERABLE {nonce}");
                if !earlier
                    .iter()
                    .filter_map(codex_user_text)
                    .any(|text| first_line(text) == steerable)
                {
                    return Err(BrokerUpstreamError::Protocol);
                }
                Planned {
                    opening: codex_created("steer", reflection)
                        + &codex_reply("steer", &format!("CW_STEERED {nonce}")),
                    later: Later::Complete,
                }
            }
            Marker::UpdateSteerable(nonce) => Planned {
                opening: codex_created("update_hold", reflection),
                later: Later::UpdateHold(update_register(reflection, &nonce)?),
            },
            Marker::UpdateRelease(nonce) => {
                update_release(reflection, &nonce)?;
                Planned {
                    opening: codex_created("update_release", reflection)
                        + &codex_reply("update_release", &format!("CW_UPDATE_RELEASE_ACK {nonce}")),
                    later: Later::Complete,
                }
            }
            Marker::UpdateSteer(nonce) => {
                let held = format!("CW_FIXTURE_UPDATE_STEERABLE {nonce}");
                if !earlier
                    .iter()
                    .filter_map(codex_user_text)
                    .any(|text| first_line(text) == held)
                {
                    return Err(BrokerUpstreamError::Protocol);
                }
                update_consume(reflection, &nonce)?;
                Planned {
                    opening: codex_created("update_steer", reflection)
                        + &codex_reply("update_steer", &format!("CW_UPDATE_STEERED {nonce}")),
                    later: Later::Complete,
                }
            }
        };
    planned.into_body(reflection).map(Some)
}

fn custody_command(nonce: &str) -> String {
    format!(
        "python3 -I -c '{}' {}",
        CUSTODY_TOOL_SCRIPT.replace('\'', "'\"'\"'"),
        nonce
    )
}

/// Marker-selected Claude Messages stream, or `None` for the canned reply.
/// Only the hold marker exists for Claude.
pub(super) fn claude(
    payload: &Value,
    reflection: &str,
) -> Result<Option<BrokerUpstreamBody>, BrokerUpstreamError> {
    let Some(text) = latest_claude_text(payload) else {
        return Ok(None);
    };
    let nonce = match marker(text)? {
        None => return Ok(None),
        Some(Marker::Hold(nonce)) => nonce,
        Some(_) => return Err(BrokerUpstreamError::Protocol),
    };
    let opening = [
        sse(
            "message_start",
            json!({"type": "message_start", "message": {
                "id": "msg_codewire_claude_hold", "type": "message", "role": "assistant",
                "model": "claude-sonnet-4-6", "content": [], "stop_reason": null,
                "stop_sequence": null, "usage": {"input_tokens": 42, "output_tokens": 0},
            }}),
        ),
        sse(
            "content_block_start",
            json!({"type": "content_block_start", "index": 0,
                "content_block": {"type": "text", "text": ""}}),
        ),
        claude_text(&format!("CWCLAUDE21238 hold broker {reflection}")),
    ]
    .concat();
    let expiry = [
        claude_text(&format!(" CW_HOLD_EXPIRED {nonce}")),
        sse(
            "content_block_stop",
            json!({"type": "content_block_stop", "index": 0}),
        ),
        sse(
            "message_delta",
            json!({"type": "message_delta",
                "delta": {"stop_reason": "end_turn", "stop_sequence": null},
                "usage": {"output_tokens": 8}}),
        ),
        sse("message_stop", json!({"type": "message_stop"})),
    ]
    .concat();
    Planned {
        opening,
        later: Later::Hold {
            keepalive: Some((
                CLAUDE_KEEPALIVE,
                sse("ping", json!({"type": "ping"})) + &flush_padding(),
            )),
            expiry,
        },
    }
    .into_body(reflection)
    .map(Some)
}

fn marker(text: &str) -> Result<Option<Marker>, BrokerUpstreamError> {
    if !text.starts_with(MARKER_PREFIX) {
        return Ok(None);
    }
    marker_line(first_line(text))
        .map(Some)
        .ok_or(BrokerUpstreamError::Protocol)
}

fn marker_line(line: &str) -> Option<Marker> {
    if let Some(command) = line.strip_prefix("CW_FIXTURE_TOOL ") {
        let (token, path) = command
            .strip_prefix("printf %s CW_TOOL_MARKER_")?
            .split_at_checked(16)?;
        let (tag, suffix) = path.strip_prefix(" > .cwnm-")?.split_at_checked(8)?;
        return (hex(token, b'A') && hex(tag, b'a') && suffix == "-tool-marker").then(|| {
            Marker::Tool {
                command: command.to_owned(),
                call_id: format!("call_cw_tool_{}", token.to_ascii_lowercase()),
            }
        });
    }
    let nonce = |prefix: &str| {
        let nonce = line.strip_prefix(prefix)?;
        (nonce.len() == 8 && hex(nonce, b'a')).then(|| nonce.to_owned())
    };
    nonce("CW_FIXTURE_HOLD ")
        .map(Marker::Hold)
        .or_else(|| nonce("CW_FIXTURE_CUSTODY ").map(Marker::Custody))
        .or_else(|| nonce("CW_FIXTURE_STEERABLE ").map(Marker::Steerable))
        .or_else(|| nonce("CW_FIXTURE_STEER ").map(Marker::Steer))
        .or_else(|| nonce("CW_FIXTURE_UPDATE_STEERABLE ").map(Marker::UpdateSteerable))
        .or_else(|| nonce("CW_FIXTURE_UPDATE_STEER ").map(Marker::UpdateSteer))
        .or_else(|| nonce("CW_FIXTURE_UPDATE_RELEASE ").map(Marker::UpdateRelease))
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum UpdateFamily {
    CodexOAuth,
    OpenAiApiKey,
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct UpdateKey {
    // The transport already validates this exact synthetic Codex credential
    // and fixed account. Keep the full scope, without a lossy hash or logs.
    scope: [u8; 32],
    family: UpdateFamily,
    nonce: [u8; 8],
}

fn update_key(reflection: &str, nonce: &str) -> Result<UpdateKey, BrokerUpstreamError> {
    let (family, scope) = if let Some(scope) = reflection.strip_prefix("cwlocalbroker") {
        (UpdateFamily::CodexOAuth, scope)
    } else if let Some(scope) = reflection.strip_prefix("cwlocalopenai") {
        (UpdateFamily::OpenAiApiKey, scope)
    } else {
        return Err(BrokerUpstreamError::Protocol);
    };
    if scope.len() != 32 || !hex(scope, b'a') {
        return Err(BrokerUpstreamError::Protocol);
    }
    if nonce.len() != 8 || !hex(nonce, b'a') {
        return Err(BrokerUpstreamError::Protocol);
    }
    Ok(UpdateKey {
        family,
        scope: scope
            .as_bytes()
            .try_into()
            .map_err(|_| BrokerUpstreamError::Protocol)?,
        nonce: nonce
            .as_bytes()
            .try_into()
            .map_err(|_| BrokerUpstreamError::Protocol)?,
    })
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum UpdatePhase {
    Held,
    ReleasedAwaitingSteer,
    Consumed,
}

struct UpdateEntry {
    token: Arc<()>,
    deadline: Instant,
    phase: UpdatePhase,
    normal_eof: bool,
    released: watch::Sender<bool>,
}

type UpdateEntries = Arc<Mutex<BTreeMap<UpdateKey, UpdateEntry>>>;

fn update_entries() -> &'static UpdateEntries {
    static ENTRIES: OnceLock<UpdateEntries> = OnceLock::new();
    ENTRIES.get_or_init(|| Arc::new(Mutex::new(BTreeMap::new())))
}

/// Construct this synchronously and move it into the whole returned body.
/// Keeping it only in the delayed future would leak a never-polled hold.
struct UpdateRegistration {
    entries: UpdateEntries,
    key: UpdateKey,
    token: Arc<()>,
    deadline: Instant,
    released: watch::Receiver<bool>,
    retained_after_eof: bool,
}

impl UpdateRegistration {
    fn waiter(&self) -> UpdateWaiter {
        UpdateWaiter {
            entries: self.entries.clone(),
            key: self.key,
            token: self.token.clone(),
            deadline: self.deadline,
            released: self.released.clone(),
        }
    }

    fn normal_eof(&mut self) {
        if self.retained_after_eof {
            return;
        }
        if let Ok(mut entries) = self.entries.lock()
            && let Some(entry) = entries.get_mut(&self.key)
            && Arc::ptr_eq(&entry.token, &self.token)
            && entry.deadline > Instant::now()
            && entry.phase == UpdatePhase::ReleasedAwaitingSteer
        {
            entry.normal_eof = true;
            self.retained_after_eof = true;
        }
    }
}

impl Drop for UpdateRegistration {
    fn drop(&mut self) {
        if !self.retained_after_eof
            && let Ok(mut entries) = self.entries.lock()
            && entries
                .get(&self.key)
                .is_some_and(|entry| Arc::ptr_eq(&entry.token, &self.token))
        {
            entries.remove(&self.key);
        }
    }
}

struct UpdateWaiter {
    entries: UpdateEntries,
    key: UpdateKey,
    token: Arc<()>,
    deadline: Instant,
    released: watch::Receiver<bool>,
}

impl UpdateWaiter {
    async fn wait(mut self) -> Result<bool, BrokerUpstreamError> {
        loop {
            {
                let entries = self
                    .entries
                    .lock()
                    .map_err(|_| BrokerUpstreamError::Protocol)?;
                let Some(entry) = entries
                    .get(&self.key)
                    .filter(|entry| Arc::ptr_eq(&entry.token, &self.token))
                else {
                    return Ok(false);
                };
                if Instant::now() >= entry.deadline {
                    return Ok(false);
                }
                if entry.phase == UpdatePhase::ReleasedAwaitingSteer {
                    return Ok(true);
                }
                if entry.phase != UpdatePhase::Held {
                    return Err(BrokerUpstreamError::Protocol);
                }
            }
            // watch latches a release sent before the body/receiver's first
            // poll. The original absolute deadline is never extended.
            tokio::select! {
                changed = self.released.changed() => {
                    if changed.is_err() { return Ok(false); }
                }
                _ = tokio::time::sleep_until(self.deadline) => {}
            }
        }
    }
}

fn update_register(
    reflection: &str,
    nonce: &str,
) -> Result<UpdateRegistration, BrokerUpstreamError> {
    let key = update_key(reflection, nonce)?;
    let entries = update_entries().clone();
    let mut locked = entries.lock().map_err(|_| BrokerUpstreamError::Protocol)?;
    let now = Instant::now();
    // Expiry is the only implicit retirement. Never evict live/released/
    // consumed evidence merely to make room for another uncertain caller.
    locked.retain(|_, entry| entry.deadline > now);
    if locked.contains_key(&key) || locked.len() >= MAXIMUM_UPDATE_REGISTRATIONS {
        return Err(BrokerUpstreamError::Protocol);
    }
    let token = Arc::new(());
    let deadline = now + UPDATE_HOLD_LIMIT;
    let (released, receiver) = watch::channel(false);
    locked.insert(
        key,
        UpdateEntry {
            token: token.clone(),
            deadline,
            phase: UpdatePhase::Held,
            normal_eof: false,
            released,
        },
    );
    drop(locked);
    Ok(UpdateRegistration {
        entries,
        key,
        token,
        deadline,
        released: receiver,
        retained_after_eof: false,
    })
}

fn update_release(reflection: &str, nonce: &str) -> Result<(), BrokerUpstreamError> {
    let key = update_key(reflection, nonce)?;
    let mut entries = update_entries()
        .lock()
        .map_err(|_| BrokerUpstreamError::Protocol)?;
    let entry = entries
        .get_mut(&key)
        .filter(|entry| entry.deadline > Instant::now() && entry.phase == UpdatePhase::Held)
        .ok_or(BrokerUpstreamError::Protocol)?;
    entry.phase = UpdatePhase::ReleasedAwaitingSteer;
    entry.released.send_replace(true);
    Ok(())
}

fn update_consume(reflection: &str, nonce: &str) -> Result<(), BrokerUpstreamError> {
    let key = update_key(reflection, nonce)?;
    let mut entries = update_entries()
        .lock()
        .map_err(|_| BrokerUpstreamError::Protocol)?;
    let entry = entries
        .get_mut(&key)
        .filter(|entry| {
            entry.deadline > Instant::now()
                && entry.phase == UpdatePhase::ReleasedAwaitingSteer
                && entry.normal_eof
        })
        .ok_or(BrokerUpstreamError::Protocol)?;
    entry.phase = UpdatePhase::Consumed;
    Ok(())
}

struct UpdateHeldBody {
    inner: BrokerUpstreamBody,
    registration: Option<UpdateRegistration>,
}

impl Stream for UpdateHeldBody {
    type Item = Result<Bytes, BrokerUpstreamError>;

    fn poll_next(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        let next = this.inner.as_mut().poll_next(context);
        match &next {
            Poll::Ready(None) => {
                if let Some(registration) = &mut this.registration {
                    registration.normal_eof();
                }
            }
            Poll::Ready(Some(Err(_))) => {
                this.registration.take();
            }
            _ => {}
        }
        next
    }
}

fn hex(value: &str, letters: u8) -> bool {
    value
        .bytes()
        .all(|byte| byte.is_ascii_digit() || (letters..letters + 6).contains(&byte))
}

fn first_line(text: &str) -> &str {
    text.split_once('\n').map_or(text, |(line, _)| line)
}

fn typed_text<'a>(part: &'a Value, kind: &str) -> Option<&'a str> {
    if part.get("type")?.as_str()? != kind {
        return None;
    }
    part.get("text")?.as_str()
}

/// A Codex user message's latest text part; `None` for every other item.
fn codex_user_text(item: &Value) -> Option<&str> {
    if item.get("role")?.as_str()? != "user"
        || item
            .get("type")
            .is_some_and(|kind| kind.as_str() != Some("message"))
    {
        return None;
    }
    match item.get("content")? {
        Value::String(text) => Some(text.as_str()),
        Value::Array(parts) => parts
            .iter()
            .rev()
            .find_map(|part| typed_text(part, "input_text")),
        _ => None,
    }
}

fn latest_codex_user(items: &[Value]) -> Option<(usize, &str)> {
    items.iter().enumerate().rev().find_map(|(index, item)| {
        codex_user_text(item)
            .filter(|text| !text.starts_with(CODEX_CONTEXT_TAG))
            .map(|text| (index, text))
    })
}

/// The latest user prompt text. Claude Code may merge consecutive user turns
/// and add reminder blocks, so only the last non-reminder text block counts.
fn latest_claude_text(payload: &Value) -> Option<&str> {
    let message = payload
        .get("messages")?
        .as_array()?
        .iter()
        .rev()
        .find(|message| message.get("role").and_then(Value::as_str) == Some("user"))?;
    match message.get("content")? {
        Value::String(text) => Some(text.as_str()),
        Value::Array(blocks) => blocks
            .iter()
            .rev()
            .filter_map(|block| typed_text(block, "text"))
            .find(|text| !text.trim_start().starts_with(CLAUDE_REMINDER_TAG)),
        _ => None,
    }
}

/// One shell call for the marker command, then exactly one completion after
/// its result. The deterministic call ID makes a repeated call impossible to
/// confuse with the first; foreign or duplicate tool activity fails closed.
fn codex_tool(
    payload: &Value,
    after: &[Value],
    command: &str,
    call_id: &str,
    reflection: &str,
) -> Result<Planned, BrokerUpstreamError> {
    let (mut call, mut output) = (None, None);
    for (index, item) in after.iter().enumerate() {
        let kind = item.get("type").and_then(Value::as_str).unwrap_or_default();
        if !TOOL_ITEM_TYPES.contains(&kind) {
            continue;
        }
        let seen = match kind {
            "function_call" | "local_shell_call" => &mut call,
            "function_call_output" => &mut output,
            _ => return Err(BrokerUpstreamError::Protocol),
        };
        if item.get("call_id").and_then(Value::as_str) != Some(call_id)
            || seen.replace(index).is_some()
        {
            return Err(BrokerUpstreamError::Protocol);
        }
    }
    let opening = match (call, output) {
        (None, None) => {
            let tool = ShellTool::offered(payload).ok_or(BrokerUpstreamError::Protocol)?;
            codex_created("tool", reflection)
                + &codex_item(tool.call(command, call_id))
                + &codex_completed("tool")
        }
        (Some(call), Some(output)) if call < output => {
            codex_created("tool_result", reflection)
                + &codex_reply("tool_result", "TOOL_MARKER_WRITTEN")
        }
        _ => return Err(BrokerUpstreamError::Protocol),
    };
    Ok(Planned {
        opening,
        later: Later::Complete,
    })
}

/// Codex shell tools in the order the fixture prefers when several are
/// offered. A tool is used only when the request offers a compatible schema.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ShellTool {
    ShellCommand,
    ExecCommand,
    Shell,
    LocalShell,
}

impl ShellTool {
    const PREFERENCE: [Self; 4] = [
        Self::ShellCommand,
        Self::ExecCommand,
        Self::Shell,
        Self::LocalShell,
    ];

    fn offered(payload: &Value) -> Option<Self> {
        let tools = payload.get("tools")?.as_array()?;
        Self::PREFERENCE
            .into_iter()
            .find(|tool| tools.iter().any(|offered| tool.accepts(offered)))
    }

    fn accepts(self, offered: &Value) -> bool {
        let kind = offered.get("type").and_then(Value::as_str);
        let (name, argument, argv) = match self {
            Self::LocalShell => return kind == Some("local_shell"),
            Self::ShellCommand => ("shell_command", "command", false),
            Self::ExecCommand => ("exec_command", "cmd", false),
            Self::Shell => ("shell", "command", true),
        };
        kind == Some("function")
            && offered.get("name").and_then(Value::as_str) == Some(name)
            && accepts_only(offered.get("parameters"), argument, argv)
    }

    fn call(self, command: &str, call_id: &str) -> Value {
        let argv = json!([SHELL_ARGV[0], SHELL_ARGV[1], command]);
        let (name, arguments) = match self {
            Self::LocalShell => {
                return json!({
                    "type": "local_shell_call", "id": "lsh_codewire_native_tool",
                    "call_id": call_id, "status": "completed",
                    "action": {"type": "exec", "command": argv},
                });
            }
            Self::ShellCommand => ("shell_command", json!({"command": command})),
            Self::ExecCommand => ("exec_command", json!({"cmd": command})),
            Self::Shell => ("shell", json!({"command": argv})),
        };
        json!({
            "type": "function_call", "id": "fc_codewire_native_tool", "status": "completed",
            "name": name, "arguments": arguments.to_string(), "call_id": call_id,
        })
    }

    fn matches_call(self, item: &Value, command: &str, call_id: &str) -> bool {
        let expected = self.call(command, call_id);
        if item.get("type") != expected.get("type")
            || item.get("call_id") != expected.get("call_id")
        {
            return false;
        }
        if self == Self::LocalShell {
            return item.get("action") == expected.get("action");
        }
        if item.get("name") != expected.get("name") {
            return false;
        }
        let parse = |value: &Value| {
            value
                .get("arguments")
                .and_then(Value::as_str)
                .and_then(|arguments| serde_json::from_str::<Value>(arguments).ok())
        };
        parse(item).is_some_and(|arguments| Some(arguments) == parse(&expected))
    }
}

/// The offered schema must type the one argument this fixture supplies and
/// require nothing else; the fixture never invents another field's value.
fn accepts_only(parameters: Option<&Value>, argument: &str, argv: bool) -> bool {
    let Some(parameters) = parameters else {
        return false;
    };
    let Some(property) = parameters
        .get("properties")
        .and_then(|properties| properties.get(argument))
    else {
        return false;
    };
    let property_type = property.get("type").and_then(Value::as_str);
    let typed = if argv {
        property_type == Some("array")
            && property
                .get("items")
                .and_then(|items| items.get("type"))
                .and_then(Value::as_str)
                == Some("string")
    } else {
        property_type == Some("string")
    };
    let required = match parameters.get("required") {
        None => true,
        Some(Value::Array(required)) => required.iter().all(|name| name == argument),
        Some(_) => false,
    };
    parameters.get("type").and_then(Value::as_str) == Some("object") && typed && required
}

fn sse(event: &str, data: Value) -> String {
    format!("event: {event}\ndata: {data}\n\n")
}

fn flush_padding() -> String {
    format!(": {}\n\n", ".".repeat(FLUSH_PADDING_BYTES))
}

fn codex_created(kind: &str, reflection: &str) -> String {
    sse(
        "response.created",
        json!({"type": "response.created", "response": {
            "id": format!("resp_codewire_native_{kind}"),
            "metadata": {"broker": reflection},
        }}),
    )
}

fn codex_item(item: Value) -> String {
    sse(
        "response.output_item.done",
        json!({"type": "response.output_item.done", "item": item}),
    )
}

fn codex_completed(kind: &str) -> String {
    sse(
        "response.completed",
        json!({"type": "response.completed", "response": {
            "id": format!("resp_codewire_native_{kind}"),
            "usage": {"input_tokens": 0, "input_tokens_details": null, "output_tokens": 0,
                "output_tokens_details": null, "total_tokens": 0},
        }}),
    )
}

/// One assistant message and the completion that ends a Codex response.
fn codex_reply(kind: &str, text: &str) -> String {
    codex_item(json!({
        "type": "message", "role": "assistant", "id": format!("msg_codewire_native_{kind}"),
        "content": [{"type": "output_text", "text": text}],
    })) + &codex_completed(kind)
}

fn claude_text(text: &str) -> String {
    sse(
        "content_block_delta",
        json!({"type": "content_block_delta", "index": 0,
            "delta": {"type": "text_delta", "text": text}}),
    )
}

/// A response whose opening is sent immediately and whose later bytes, if
/// any, arrive on timers owned by the returned stream.
struct Planned {
    opening: String,
    later: Later,
}

enum Later {
    Complete,
    After(Duration, String),
    Hold {
        keepalive: Option<(Duration, String)>,
        expiry: String,
    },
    UpdateHold(UpdateRegistration),
}

impl Planned {
    fn into_body(self, reflection: &str) -> Result<BrokerUpstreamBody, BrokerUpstreamError> {
        let mut opening = self.opening;
        if !matches!(self.later, Later::Complete) {
            opening.push_str(&flush_padding());
        }
        // Split inside the reflected value, not at an SSE boundary.
        let split_at = opening
            .find(reflection)
            .ok_or(BrokerUpstreamError::Protocol)?
            + reflection.len() / 2;
        let opening = stream::iter([
            Ok(Bytes::copy_from_slice(&opening.as_bytes()[..split_at])),
            Ok(Bytes::copy_from_slice(&opening.as_bytes()[split_at..])),
        ]);
        Ok(match self.later {
            Later::Complete => Box::pin(opening),
            Later::After(delay, tail) => Box::pin(opening.chain(stream::once(async move {
                tokio::time::sleep(delay).await;
                Ok(Bytes::from(tail))
            }))),
            Later::UpdateHold(registration) => {
                let waiter = registration.waiter();
                let nonce = String::from_utf8(registration.key.nonce.to_vec())
                    .map_err(|_| BrokerUpstreamError::Protocol)?;
                let later = stream::once(async move {
                    let released = waiter.wait().await?;
                    let text = if released {
                        format!("CW_UPDATE_RELEASED {nonce}")
                    } else {
                        format!("CW_UPDATE_HOLD_EXPIRED {nonce}")
                    };
                    Ok(Bytes::from(codex_reply("update_hold", &text)))
                });
                Box::pin(UpdateHeldBody {
                    inner: Box::pin(opening.chain(later)),
                    registration: Some(registration),
                })
            }
            Later::Hold { keepalive, expiry } => {
                let (every, ping) = keepalive
                    .map_or((Duration::ZERO, Bytes::new()), |(every, ping)| {
                        (every, Bytes::from(ping))
                    });
                let pings = HOLD_LIMIT
                    .as_secs()
                    .checked_div(every.as_secs())
                    .unwrap_or(0);
                let pings = u32::try_from(pings).map_err(|_| BrokerUpstreamError::Protocol)?;
                let keepalives = stream::iter(0..pings).then(move |_| {
                    let ping = ping.clone();
                    async move {
                        tokio::time::sleep(every).await;
                        Ok(ping)
                    }
                });
                let remainder = HOLD_LIMIT.saturating_sub(every * pings);
                Box::pin(opening.chain(keepalives).chain(stream::once(async move {
                    tokio::time::sleep(remainder).await;
                    Ok(Bytes::from(expiry))
                })))
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use av_credential_proxy::{RedactionSet, StreamingRedactor};
    use codewire_access::CredentialAuthKind;
    use futures::FutureExt as _;
    use http::{HeaderMap, HeaderName, HeaderValue, Method};
    use tokio::time::{Instant, timeout};
    use url::Url;
    use zeroize::Zeroizing;

    use super::*;
    use crate::anthropic::{AnthropicApiKeyAdapter, AnthropicStreamingResponse};
    use crate::http_test_support::Lease;
    use crate::runtime::{
        BrokerUpstreamRequest, BrokerUpstreamTransport as _, SYNTHETIC_CODEX_ACCOUNT_ID,
        SyntheticOpenAiSmokeTransport,
    };
    use crate::{OpenAiApiKeyAdapter, OpenAiStreamingResponse};

    const CODEX_KEY: &str = "cwlocalbroker0123456789abcdef0123456789abcdef";
    const OPENAI_KEY: &str = "cwlocalopenai0123456789abcdef0123456789abcdef";
    const ANTHROPIC_KEY: &str = "cwlocalanthropic0123456789abcdef0123456789abcdef";
    const OTHER_CODEX_KEY: &str = "cwlocalbrokerfedcba9876543210fedcba9876543210";
    const TOOL_COMMAND: &str =
        "printf %s CW_TOOL_MARKER_0123456789ABCDEF > .cwnm-0a1b2c3d-tool-marker";
    const CALL_ID: &str = "call_cw_tool_0123456789abcdef";

    trait Redact {
        fn push(&mut self, chunk: &[u8]) -> Vec<u8>;
        fn finish(self: Box<Self>) -> Vec<u8>;
    }

    impl Redact for StreamingRedactor {
        fn push(&mut self, chunk: &[u8]) -> Vec<u8> {
            StreamingRedactor::push(self, chunk)
        }
        fn finish(mut self: Box<Self>) -> Vec<u8> {
            StreamingRedactor::finish(&mut self)
        }
    }

    impl Redact for OpenAiStreamingResponse {
        fn push(&mut self, chunk: &[u8]) -> Vec<u8> {
            OpenAiStreamingResponse::push(self, chunk).unwrap()
        }
        fn finish(self: Box<Self>) -> Vec<u8> {
            OpenAiStreamingResponse::finish(*self).unwrap()
        }
    }

    impl Redact for AnthropicStreamingResponse {
        fn push(&mut self, chunk: &[u8]) -> Vec<u8> {
            AnthropicStreamingResponse::push(self, chunk).unwrap()
        }
        fn finish(self: Box<Self>) -> Vec<u8> {
            AnthropicStreamingResponse::finish(*self).unwrap()
        }
    }

    /// The guest's view of one response: every raw chunk is checked for the
    /// whole injected value before redaction, as the broker would forward it.
    struct Client {
        body: BrokerUpstreamBody,
        redaction: Box<dyn Redact>,
        key: &'static str,
        received: String,
    }

    impl Client {
        async fn start(request: BrokerUpstreamRequest, key: &'static str) -> Self {
            let redaction = RedactionSet::new([key.to_owned(), format!("Bearer {key}")]);
            Self::with(request, key, Box::new(redaction.into_streaming())).await
        }

        async fn with(
            request: BrokerUpstreamRequest,
            key: &'static str,
            redaction: Box<dyn Redact>,
        ) -> Self {
            let response = SyntheticOpenAiSmokeTransport
                .execute(request)
                .await
                .unwrap_or_else(|_| panic!("fixture rejected the request"));
            let (_, _, body) = response.into_parts();
            Self {
                body,
                redaction,
                key,
                received: String::new(),
            }
        }

        async fn read(&mut self, chunks: usize) {
            for _ in 0..chunks {
                let chunk = self.body.next().await.expect("chunk").unwrap();
                assert!(
                    !chunk
                        .windows(self.key.len())
                        .any(|window| window == self.key.as_bytes())
                );
                let redacted = self.redaction.push(&chunk);
                self.received
                    .push_str(std::str::from_utf8(&redacted).unwrap());
            }
        }

        async fn finish(mut self) -> String {
            while let Some(chunk) = self.body.next().await {
                let chunk = chunk.unwrap();
                assert!(
                    !chunk
                        .windows(self.key.len())
                        .any(|window| window == self.key.as_bytes())
                );
                let redacted = self.redaction.push(&chunk);
                self.received
                    .push_str(std::str::from_utf8(&redacted).unwrap());
            }
            let tail = self.redaction.finish();
            self.received.push_str(std::str::from_utf8(&tail).unwrap());
            assert!(!self.received.contains(self.key));
            self.received
        }
    }

    /// Complete SSE events, skipping comments and any unterminated tail.
    fn events(text: &str) -> Vec<Value> {
        let mut blocks = text.split("\n\n").collect::<Vec<_>>();
        blocks.pop();
        blocks
            .into_iter()
            .filter(|block| !block.starts_with(':'))
            .map(|block| {
                let (event, data) = block.split_once('\n').unwrap();
                let data: Value =
                    serde_json::from_str(data.strip_prefix("data: ").unwrap()).unwrap();
                assert_eq!(event.strip_prefix("event: "), data["type"].as_str());
                data
            })
            .collect()
    }

    fn types(events: &[Value]) -> Vec<&str> {
        events
            .iter()
            .map(|event| event["type"].as_str().unwrap())
            .collect()
    }

    fn user(text: &str) -> Value {
        json!({"type": "message", "role": "user",
            "content": [{"type": "input_text", "text": text}]})
    }

    fn function_tool(name: &str, properties: Value, required: Value) -> Value {
        json!({"type": "function", "name": name, "description": "", "strict": false,
            "parameters": {"type": "object", "properties": properties,
                "required": required, "additionalProperties": false}})
    }

    fn shell_command_tool() -> Value {
        function_tool(
            "shell_command",
            json!({"command": {"type": "string"}, "workdir": {"type": "string"},
                "timeout_ms": {"type": "number"}, "login": {"type": "boolean"}}),
            json!(["command"]),
        )
    }

    /// Codex-shaped Responses body: developer and context items precede the
    /// prompt, and unrelated tools are offered beside any shell tool.
    fn codex_body(after_context: Vec<Value>, tools: Vec<Value>) -> Value {
        let mut input = vec![
            json!({"type": "message", "role": "developer",
                "content": [{"type": "input_text", "text": "<permissions instructions>"}]}),
            user("<environment_context>\n  <cwd>/workspace</cwd>\n</environment_context>"),
        ];
        input.extend(after_context);
        let mut offered = vec![
            function_tool(
                "update_plan",
                json!({"plan": {"type": "array", "items": {"type": "object"}}}),
                json!(["plan"]),
            ),
            json!({"type": "custom", "name": "apply_patch", "description": "",
                "format": {"type": "grammar"}}),
        ];
        offered.extend(tools);
        json!({"model": "gpt-5-codex", "instructions": "", "input": input,
            "tools": offered, "tool_choice": "auto", "parallel_tool_calls": false,
            "reasoning": null, "store": false, "stream": true})
    }

    fn codex_request(body: &Value) -> BrokerUpstreamRequest {
        BrokerUpstreamRequest {
            method: Method::POST,
            target: Url::parse("https://chatgpt.com/backend-api/codex/responses").unwrap(),
            headers: HeaderMap::from_iter([
                (
                    http::header::AUTHORIZATION,
                    HeaderValue::from_str(&format!("Bearer {CODEX_KEY}")).unwrap(),
                ),
                (
                    HeaderName::from_static("chatgpt-account-id"),
                    HeaderValue::from_static(SYNTHETIC_CODEX_ACCOUNT_ID),
                ),
            ]),
            body: serde_json::to_vec(body).unwrap(),
        }
    }

    fn claude_body(messages: Value) -> Value {
        json!({"model": "claude-sonnet-4-6", "max_tokens": 64, "stream": true,
            "messages": messages})
    }

    fn claude_request(body: &Value) -> BrokerUpstreamRequest {
        BrokerUpstreamRequest {
            method: Method::POST,
            target: Url::parse("https://api.anthropic.com/v1/messages?beta=true").unwrap(),
            headers: HeaderMap::from_iter([
                (
                    http::header::CONTENT_TYPE,
                    HeaderValue::from_static("application/json"),
                ),
                (
                    http::header::ACCEPT_ENCODING,
                    HeaderValue::from_static("identity"),
                ),
                (
                    HeaderName::from_static("anthropic-version"),
                    HeaderValue::from_static("2023-06-01"),
                ),
                (
                    HeaderName::from_static("x-api-key"),
                    HeaderValue::from_static(ANTHROPIC_KEY),
                ),
            ]),
            body: serde_json::to_vec(body).unwrap(),
        }
    }

    async fn raw(request: BrokerUpstreamRequest) -> Vec<u8> {
        let (_, _, mut body) = SyntheticOpenAiSmokeTransport
            .execute(request)
            .await
            .unwrap_or_else(|_| panic!("fixture rejected the request"))
            .into_parts();
        let mut output = Vec::new();
        while let Some(chunk) = body.next().await {
            output.extend_from_slice(&chunk.unwrap());
        }
        output
    }

    async fn rejected(request: BrokerUpstreamRequest) -> bool {
        matches!(
            SyntheticOpenAiSmokeTransport.execute(request).await,
            Err(BrokerUpstreamError::Protocol)
        )
    }

    fn reply_text(events: &[Value]) -> Vec<&str> {
        events
            .iter()
            .filter(|event| event["type"] == "response.output_item.done")
            .map(|event| event["item"]["content"][0]["text"].as_str().unwrap())
            .collect()
    }

    /// Registry tests share the production process-local registry. Serialize
    /// them before constructing each paused runtime; retire only expired
    /// evidence through the real authenticated transport after the assertions.
    fn update_test(body: impl std::future::Future<Output = ()>) {
        static TEST_LOCK: Mutex<()> = Mutex::new(());
        let _serial = TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .start_paused(true)
            .build()
            .unwrap();
        runtime.block_on(async {
            let result = std::panic::AssertUnwindSafe(body).catch_unwind().await;
            tokio::time::advance(Duration::from_secs(601)).await;
            let request = update_request("STEERABLE", "0fffffff");
            let cleanup = SyntheticOpenAiSmokeTransport.execute(request).await;
            match cleanup {
                Ok(response) => drop(response), // exact new body guard removes its own entry
                Err(_) if result.is_ok() => panic!("update fixture cleanup was refused"),
                Err(_) => {}
            }
            if let Err(panic) = result {
                std::panic::resume_unwind(panic);
            }
        });
    }

    fn update_request(action: &str, nonce: &str) -> BrokerUpstreamRequest {
        codex_request(&codex_body(
            vec![user(&format!("CW_FIXTURE_UPDATE_{action} {nonce}"))],
            Vec::new(),
        ))
    }

    fn update_steer_request(nonce: &str) -> BrokerUpstreamRequest {
        codex_request(&codex_body(
            vec![
                user(&format!("CW_FIXTURE_UPDATE_STEERABLE {nonce}")),
                json!({"type":"message", "role":"assistant", "content":[{
                    "type":"output_text", "text":format!("CW_UPDATE_RELEASED {nonce}")
                }]}),
                user(&format!("CW_FIXTURE_UPDATE_STEER {nonce}")),
            ],
            Vec::new(),
        ))
    }

    fn with_codex_scope(
        mut request: BrokerUpstreamRequest,
        key: &'static str,
    ) -> BrokerUpstreamRequest {
        request.headers.insert(
            http::header::AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {key}")).unwrap(),
        );
        request
    }

    fn response_client(response: crate::runtime::BrokerUpstreamResponse) -> Client {
        let (_, _, body) = response.into_parts();
        let redaction = RedactionSet::new([CODEX_KEY.to_owned(), format!("Bearer {CODEX_KEY}")]);
        Client {
            body,
            redaction: Box::new(redaction.into_streaming()),
            key: CODEX_KEY,
            received: String::new(),
        }
    }

    #[test]
    fn marker_grammar_is_closed_and_exact() {
        assert_eq!(
            marker(&format!(
                "CW_FIXTURE_TOOL {TOOL_COMMAND}\nUse your shell tool."
            ))
            .unwrap(),
            Some(Marker::Tool {
                command: TOOL_COMMAND.to_owned(),
                call_id: CALL_ID.to_owned(),
            })
        );
        for (text, expected) in [
            (
                "CW_FIXTURE_CUSTODY 0a1b2c3d\nRun only the supplied fixture.",
                Marker::Custody("0a1b2c3d".into()),
            ),
            (
                "CW_FIXTURE_HOLD 0a1b2c3d\nWait.",
                Marker::Hold("0a1b2c3d".into()),
            ),
            ("CW_FIXTURE_HOLD 0a1b2c3d", Marker::Hold("0a1b2c3d".into())),
            (
                "CW_FIXTURE_STEERABLE 0a1b2c3d\nWait.",
                Marker::Steerable("0a1b2c3d".into()),
            ),
            (
                "CW_FIXTURE_STEER 0a1b2c3d\nFinish.",
                Marker::Steer("0a1b2c3d".into()),
            ),
        ] {
            assert_eq!(marker(text).unwrap(), Some(expected));
        }
        for text in [
            "Reply with exactly CW_TURN_TWO. Do not use tools.",
            " CW_FIXTURE_HOLD 0a1b2c3d",
            "[Codewire] Managed worker finished: CW_FIXTURE_HOLD 0a1b2c3d",
            "cw_fixture_hold 0a1b2c3d",
            "",
        ] {
            assert_eq!(marker(text).unwrap(), None, "{text}");
        }
        for text in [
            "CW_FIXTURE_",
            "CW_FIXTURE_CUSTODY",
            "CW_FIXTURE_CUSTODY 0A1B2C3D",
            "CW_FIXTURE_CUSTODY 0a1b2c3d ",
            "CW_FIXTURE_CUSTODY 0a1b2c3d; echo unsafe",
            "CW_FIXTURE_CUSTODY ../0a1b2c3d",
            "CW_FIXTURE_CUSTODY 0a1b2c3d\r\nWait.",
            "CW_FIXTURE_HOLD",
            "CW_FIXTURE_HOLD ",
            "CW_FIXTURE_HOLD 0a1b2c3",
            "CW_FIXTURE_HOLD 0a1b2c3d4",
            "CW_FIXTURE_HOLD 0A1B2C3D",
            "CW_FIXTURE_HOLD 0a1b2c3g",
            "CW_FIXTURE_HOLD  0a1b2c3d",
            "CW_FIXTURE_HOLD 0a1b2c3d ",
            "CW_FIXTURE_HOLD 0a1b2c3d\r\nWait.",
            "CW_FIXTURE_HOLDX 0a1b2c3d",
            "CW_FIXTURE_STEERABLE",
            "CW_FIXTURE_STEER 0a1b",
            "CW_FIXTURE_OTHER 0a1b2c3d",
            "CW_FIXTURE_TOOL",
            "CW_FIXTURE_TOOL printf %s CW_TOOL_MARKER_0123456789abcdef > .cwnm-0a1b2c3d-tool-marker",
            "CW_FIXTURE_TOOL printf %s CW_TOOL_MARKER_0123456789ABCDE > .cwnm-0a1b2c3d-tool-marker",
            "CW_FIXTURE_TOOL printf %s CW_TOOL_MARKER_0123456789ABCDEF0 > .cwnm-0a1b2c3d-tool-marker",
            "CW_FIXTURE_TOOL printf %s CW_TOOL_MARKER_0123456789ABCDEF > .cwnm-0A1B2C3D-tool-marker",
            "CW_FIXTURE_TOOL printf %s CW_TOOL_MARKER_0123456789ABCDEF > .cwnm-0a1b2c3-tool-marker",
            "CW_FIXTURE_TOOL printf %s CW_TOOL_MARKER_0123456789ABCDEF > cwnm-0a1b2c3d-tool-marker",
            "CW_FIXTURE_TOOL printf %s CW_TOOL_MARKER_0123456789ABCDEF >> .cwnm-0a1b2c3d-tool-marker",
            "CW_FIXTURE_TOOL printf %s CW_TOOL_MARKER_0123456789ABCDEF > .cwnm-0a1b2c3d-tool-marker; rm -rf /",
            "CW_FIXTURE_TOOL printf %s CW_TOOL_MARKER_0123456789ABCDEF > /tmp/.cwnm-0a1b2c3d-tool-marker",
            "CW_FIXTURE_TOOL echo CW_TOOL_MARKER_0123456789ABCDEF > .cwnm-0a1b2c3d-tool-marker",
            "CW_FIXTURE_TOOL  printf %s CW_TOOL_MARKER_0123456789ABCDEF > .cwnm-0a1b2c3d-tool-marker",
        ] {
            assert!(
                matches!(marker(text), Err(BrokerUpstreamError::Protocol)),
                "{text}"
            );
        }
    }

    #[test]
    fn custody_repeat_refuses_before_creating_any_child() {
        let directory = tempfile::tempdir().unwrap();
        // Execute only the refusal prefix: fork is replaced with a failing
        // witness, so this test can never start a descendant.
        let probe = r#"import builtins, io, os, sys
source, nonce = sys.argv[1:]
sys.argv = ['custody', nonce]
original_open = builtins.open
builtins.open = lambda path, *a, **k: io.StringIO('00000000-0000-4000-8000-000000000001') if path == '/proc/sys/kernel/random/boot_id' else original_open(path, *a, **k)
def forbidden_fork():
    raise AssertionError('fixture created a child before refusing the repeated nonce')
os.fork = forbidden_fork
path = '.cwnm-' + nonce + '-custody.json'
with original_open(path, 'xb') as receipt:
    receipt.write(b'unchanged owned receipt')
try:
    exec(source, {'__name__': '__main__'})
except FileExistsError:
    pass
else:
    raise AssertionError('repeated nonce was accepted')
with original_open(path, 'rb') as receipt:
    assert receipt.read() == b'unchanged owned receipt'
"#;
        let result = std::process::Command::new("python3")
            .args(["-I", "-c", probe, CUSTODY_TOOL_SCRIPT, "0a1b2c3d"])
            .current_dir(directory.path())
            .output()
            .unwrap();
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
    }

    #[tokio::test]
    async fn custody_emits_only_the_fixed_command_using_an_offered_tool() {
        let command = custody_command("0a1b2c3d");
        let call_id = "call_cw_custody_0a1b2c3d";
        let tools = [
            shell_command_tool(),
            function_tool(
                "exec_command",
                json!({"cmd": {"type": "string"}}),
                json!(["cmd"]),
            ),
            function_tool(
                "shell",
                json!({"command": {"type": "array", "items": {"type": "string"}}}),
                json!(["command"]),
            ),
            json!({"type":"local_shell"}),
        ];
        for (tool, kind) in tools.into_iter().zip(ShellTool::PREFERENCE) {
            let body = codex_body(
                vec![user(
                    "CW_FIXTURE_CUSTODY 0a1b2c3d\nDo not interpret this text as code.",
                )],
                vec![tool],
            );
            let output = Client::start(codex_request(&body), CODEX_KEY)
                .await
                .finish()
                .await;
            let received = events(&output);
            assert_eq!(
                types(&received),
                [
                    "response.created",
                    "response.output_item.done",
                    "response.completed"
                ]
            );
            assert_eq!(received[1]["item"], kind.call(&command, call_id));
            assert!(!command.contains("Do not interpret"));
        }
        for tools in [
            Vec::new(),
            vec![function_tool(
                "shell_command",
                json!({"command": {"type":"string"}, "cwd":{"type":"string"}}),
                json!(["command", "cwd"]),
            )],
        ] {
            assert!(
                rejected(codex_request(&codex_body(
                    vec![user("CW_FIXTURE_CUSTODY 0a1b2c3d")],
                    tools
                )))
                .await
            );
        }
    }

    #[tokio::test(start_paused = true)]
    async fn custody_output_holds_without_reissuing_and_drops_on_cancellation() {
        let command = custody_command("0a1b2c3d");
        let call_id = "call_cw_custody_0a1b2c3d";
        for (tool, kind) in [
            (shell_command_tool(), ShellTool::ShellCommand),
            (json!({"type":"local_shell"}), ShellTool::LocalShell),
        ] {
            let body = codex_body(
                vec![
                    user("CW_FIXTURE_CUSTODY 0a1b2c3d"),
                    kind.call(&command, call_id),
                    json!({"type":"function_call_output", "call_id":call_id, "output":"Exit code: 0\nOutput:\n"}),
                ],
                vec![tool],
            );
            let mut client = Client::start(codex_request(&body), CODEX_KEY).await;
            client.read(2).await;
            assert_eq!(types(&events(&client.received)), ["response.created"]);
            assert!(!client.received.contains("function_call"));
            assert!(
                timeout(Duration::from_secs(60), client.body.next())
                    .await
                    .is_err()
            );
            drop(client);
            assert_eq!(
                tokio::runtime::Handle::current()
                    .metrics()
                    .num_alive_tasks(),
                0
            );
        }
    }

    #[tokio::test(start_paused = true)]
    async fn custody_uncancelled_hold_has_bounded_distinct_expiry() {
        let start = Instant::now();
        let call_id = "call_cw_custody_0a1b2c3d";
        let body = codex_body(
            vec![
                user("CW_FIXTURE_CUSTODY 0a1b2c3d"),
                ShellTool::ShellCommand.call(&custody_command("0a1b2c3d"), call_id),
                json!({"type":"function_call_output", "call_id":call_id, "output":"Exit code: 0"}),
            ],
            vec![shell_command_tool()],
        );
        let output = Client::start(codex_request(&body), CODEX_KEY)
            .await
            .finish()
            .await;
        assert_eq!(start.elapsed(), HOLD_LIMIT);
        assert_eq!(
            reply_text(&events(&output)),
            ["CW_CUSTODY_EXPIRED 0a1b2c3d"]
        );
        assert!(!output.contains("function_call"));
    }

    #[tokio::test]
    async fn custody_refuses_changed_command_duplicate_or_incomplete_history() {
        let call_id = "call_cw_custody_0a1b2c3d";
        let prompt = user("CW_FIXTURE_CUSTODY 0a1b2c3d");
        let call = ShellTool::ShellCommand.call(&custody_command("0a1b2c3d"), call_id);
        let output =
            json!({"type":"function_call_output", "call_id":call_id, "output":"Exit code: 0"});
        let mut changed = call.clone();
        changed["arguments"] =
            json!(json!({"command":"echo arbitrary incoming command"}).to_string());
        let mut wrong_tool = call.clone();
        wrong_tool["name"] = json!("exec_command");
        for history in [
            vec![prompt.clone(), call.clone()],
            vec![prompt.clone(), output.clone()],
            vec![prompt.clone(), output.clone(), call.clone()],
            vec![prompt.clone(), call.clone(), output.clone(), call.clone()],
            vec![prompt.clone(), call.clone(), output.clone(), output.clone()],
            vec![prompt.clone(), changed, output.clone()],
            vec![prompt.clone(), wrong_tool, output.clone()],
        ] {
            assert!(
                rejected(codex_request(&codex_body(
                    history,
                    vec![shell_command_tool()]
                )))
                .await
            );
        }
        let mut request = codex_request(&codex_body(vec![prompt], vec![shell_command_tool()]));
        request.headers.insert(
            "chatgpt-account-id",
            HeaderValue::from_static("account-other"),
        );
        assert!(rejected(request).await);
    }

    #[tokio::test]
    async fn codex_tool_marker_yields_one_exact_call_for_the_offered_shell_tool() {
        let argv = json!(["bash", "-lc", TOOL_COMMAND]);
        let cases = [
            (
                shell_command_tool(),
                json!({"type": "function_call", "id": "fc_codewire_native_tool",
                    "status": "completed", "name": "shell_command",
                    "arguments": json!({"command": TOOL_COMMAND}).to_string(),
                    "call_id": CALL_ID}),
            ),
            (
                function_tool(
                    "exec_command",
                    json!({"cmd": {"type": "string"}, "yield_time_ms": {"type": "number"}}),
                    json!(["cmd"]),
                ),
                json!({"type": "function_call", "id": "fc_codewire_native_tool",
                    "status": "completed", "name": "exec_command",
                    "arguments": json!({"cmd": TOOL_COMMAND}).to_string(),
                    "call_id": CALL_ID}),
            ),
            (
                function_tool(
                    "shell",
                    json!({"command": {"type": "array", "items": {"type": "string"}},
                        "workdir": {"type": "string"}}),
                    json!(["command"]),
                ),
                json!({"type": "function_call", "id": "fc_codewire_native_tool",
                    "status": "completed", "name": "shell",
                    "arguments": json!({"command": argv}).to_string(),
                    "call_id": CALL_ID}),
            ),
            (
                json!({"type": "local_shell"}),
                json!({"type": "local_shell_call", "id": "lsh_codewire_native_tool",
                    "call_id": CALL_ID, "status": "completed",
                    "action": {"type": "exec", "command": argv}}),
            ),
        ];
        for (tool, expected) in cases {
            let body = codex_body(
                vec![user(&format!(
                    "CW_FIXTURE_TOOL {TOOL_COMMAND}\nUse your shell command tool."
                ))],
                vec![tool],
            );
            let output = Client::start(codex_request(&body), CODEX_KEY)
                .await
                .finish()
                .await;
            let events = events(&output);
            assert_eq!(
                types(&events),
                [
                    "response.created",
                    "response.output_item.done",
                    "response.completed"
                ]
            );
            assert_eq!(events[0]["response"]["metadata"]["broker"], "[REDACTED]");
            assert_eq!(events[1]["item"], expected);
        }
    }

    #[tokio::test]
    async fn codex_tool_marker_never_invents_an_unoffered_or_incompatible_tool() {
        let prompt = || vec![user(&format!("CW_FIXTURE_TOOL {TOOL_COMMAND}"))];
        let mut cases = vec![
            codex_body(prompt(), Vec::new()),
            codex_body(
                prompt(),
                vec![function_tool(
                    "shell_command",
                    json!({"command": {"type": "string"}, "workdir": {"type": "string"}}),
                    json!(["command", "workdir"]),
                )],
            ),
            codex_body(
                prompt(),
                vec![function_tool(
                    "shell_command",
                    json!({"command": {"type": "array", "items": {"type": "string"}}}),
                    json!(["command"]),
                )],
            ),
            codex_body(
                prompt(),
                vec![function_tool(
                    "shell",
                    json!({"command": {"type": "string"}}),
                    json!(["command"]),
                )],
            ),
            codex_body(
                prompt(),
                vec![function_tool(
                    "exec_command",
                    json!({"command": {"type": "string"}}),
                    json!(["command"]),
                )],
            ),
            codex_body(
                prompt(),
                vec![function_tool(
                    "run_shell",
                    json!({"command": {"type": "string"}}),
                    json!(["command"]),
                )],
            ),
        ];
        let mut without_tools = codex_body(prompt(), Vec::new());
        without_tools.as_object_mut().unwrap().remove("tools");
        cases.push(without_tools);
        for body in cases {
            assert!(rejected(codex_request(&body)).await, "{body}");
        }
    }

    #[tokio::test]
    async fn codex_tool_result_completes_without_repeating_the_call() {
        let prompt = user(&format!(
            "CW_FIXTURE_TOOL {TOOL_COMMAND}\nUse your shell command tool."
        ));
        let call = json!({"type": "function_call", "name": "shell_command",
            "arguments": json!({"command": TOOL_COMMAND}).to_string(), "call_id": CALL_ID});
        let local_call = json!({"type": "local_shell_call", "call_id": CALL_ID,
            "status": "completed",
            "action": {"type": "exec", "command": ["bash", "-lc", TOOL_COMMAND]}});
        let output = json!({"type": "function_call_output", "call_id": CALL_ID,
            "output": "Exit code: 0\nOutput:\n"});
        for history in [
            vec![prompt.clone(), call.clone(), output.clone()],
            vec![prompt.clone(), local_call, output.clone()],
        ] {
            let body = codex_body(history, vec![shell_command_tool()]);
            let received = Client::start(codex_request(&body), CODEX_KEY)
                .await
                .finish()
                .await;
            let events = events(&received);
            assert_eq!(
                types(&events),
                [
                    "response.created",
                    "response.output_item.done",
                    "response.completed"
                ]
            );
            assert_eq!(events[1]["item"]["type"], "message");
            assert_eq!(reply_text(&events), ["TOOL_MARKER_WRITTEN"]);
        }

        let foreign = json!({"type": "function_call", "name": "shell_command",
            "arguments": "{}", "call_id": "call_other"});
        let foreign_output = json!({"type": "function_call_output",
            "call_id": "call_other", "output": ""});
        let custom = json!({"type": "custom_tool_call", "name": "apply_patch",
            "input": "", "call_id": CALL_ID});
        for history in [
            vec![prompt.clone(), call.clone()],
            vec![prompt.clone(), output.clone()],
            vec![prompt.clone(), output.clone(), call.clone()],
            vec![prompt.clone(), call.clone(), output.clone(), call.clone()],
            vec![prompt.clone(), call.clone(), output.clone(), output.clone()],
            vec![prompt.clone(), foreign, foreign_output],
            vec![prompt.clone(), custom],
        ] {
            let body = codex_body(history, vec![shell_command_tool()]);
            assert!(rejected(codex_request(&body)).await, "{body}");
        }
    }

    #[tokio::test]
    async fn codex_requests_without_a_latest_marker_keep_the_canned_bytes() {
        let canned = raw(codex_request(&json!({"input": "hello"}))).await;
        assert!(
            String::from_utf8(canned.clone())
                .unwrap()
                .contains("CWCODEX149 broker ")
        );
        // Later turns, parent notifications and turns after an interrupted
        // hold keep the canned reply even when history still holds a marker.
        let after_tool = vec![
            user(&format!("CW_FIXTURE_TOOL {TOOL_COMMAND}")),
            json!({"type": "function_call", "name": "shell_command", "arguments": "{}",
                "call_id": CALL_ID}),
            json!({"type": "function_call_output", "call_id": CALL_ID, "output": ""}),
            json!({"type": "message", "role": "assistant",
                "content": [{"type": "output_text", "text": "TOOL_MARKER_WRITTEN"}]}),
            user("Reply with exactly CW_LEAD_CONTINUED. Do not use tools."),
        ];
        let after_hold = vec![
            user("CW_FIXTURE_HOLD 0a1b2c3d\nWait for further input before replying."),
            user("<turn_aborted>\nThe user interrupted the previous turn.\n</turn_aborted>"),
            user("[Codewire] Managed worker message completed. CW_FIXTURE_HOLD 0a1b2c3d"),
        ];
        let bodies = [
            codex_body(
                vec![user("Reply with exactly CW_TURN_TWO. Do not use tools.")],
                vec![shell_command_tool()],
            ),
            codex_body(after_tool, vec![shell_command_tool()]),
            codex_body(after_hold, vec![shell_command_tool()]),
            json!({"input": 42}),
            json!({"input": []}),
        ];
        for body in bodies {
            assert_eq!(raw(codex_request(&body)).await, canned, "{body}");
        }
        let mut request = codex_request(&json!({}));
        request.body = b"not JSON".to_vec();
        assert_eq!(raw(request).await, canned);
    }

    #[tokio::test(start_paused = true)]
    async fn codex_hold_opens_flushed_stream_and_stays_open_until_cancelled() {
        let start = Instant::now();
        // The API-key route proves the production response policy flushes the
        // opening event through its redactor before the hold.
        let mut lease = Lease::new(
            "openai",
            CredentialAuthKind::ApiKey,
            "openai",
            "responses",
            "openai-api",
        );
        lease.material = Zeroizing::new(OPENAI_KEY.as_bytes().to_vec());
        let body = codex_body(
            vec![user(
                "CW_FIXTURE_HOLD 0a1b2c3d\nWait for further input before replying.",
            )],
            vec![shell_command_tool()],
        );
        let (method, target, headers, body, policy) = OpenAiApiKeyAdapter::new()
            .unwrap()
            .prepare(
                lease,
                &Method::POST,
                "/responses",
                None,
                &HeaderMap::from_iter([(
                    http::header::CONTENT_TYPE,
                    HeaderValue::from_static("application/json"),
                )]),
                &serde_json::to_vec(&body).unwrap(),
            )
            .unwrap()
            .into_parts();
        let request = BrokerUpstreamRequest {
            method,
            target,
            headers,
            body,
        };
        let (status, upstream_headers, upstream_body) = SyntheticOpenAiSmokeTransport
            .execute(request)
            .await
            .unwrap_or_else(|_| panic!("fixture rejected the request"))
            .into_parts();
        assert_eq!(status, http::StatusCode::OK);
        let (headers, redaction) = policy.begin(&upstream_headers).unwrap();
        assert_eq!(headers["x-request-id"], "[REDACTED]");
        let mut client = Client {
            body: upstream_body,
            redaction: Box::new(redaction),
            key: OPENAI_KEY,
            received: String::new(),
        };
        client.read(2).await;
        assert_eq!(start.elapsed(), Duration::ZERO);
        let opened = events(&client.received);
        assert_eq!(types(&opened), ["response.created"]);
        assert_eq!(opened[0]["response"]["metadata"]["broker"], "[REDACTED]");

        assert!(
            timeout(Duration::from_secs(60), client.body.next())
                .await
                .is_err()
        );
        assert_eq!(start.elapsed(), Duration::from_secs(60));
        // Cancellation is the client dropping the body; the hold owns no task.
        drop(client);
        assert_eq!(
            tokio::runtime::Handle::current()
                .metrics()
                .num_alive_tasks(),
            0
        );
    }

    #[tokio::test(start_paused = true)]
    async fn uncancelled_codex_hold_ends_at_its_bound_with_expiry_text() {
        let start = Instant::now();
        let body = codex_body(
            vec![user("CW_FIXTURE_HOLD 0a1b2c3d\nWait.")],
            vec![shell_command_tool()],
        );
        let output = Client::start(codex_request(&body), CODEX_KEY)
            .await
            .finish()
            .await;
        assert_eq!(start.elapsed(), HOLD_LIMIT);
        let events = events(&output);
        assert_eq!(
            types(&events),
            [
                "response.created",
                "response.output_item.done",
                "response.completed"
            ]
        );
        assert_eq!(reply_text(&events), ["CW_HOLD_EXPIRED 0a1b2c3d"]);
    }

    #[test]
    fn codex_update_release_latches_before_the_held_body_first_poll() {
        update_test(async {
            let held =
                user("CW_FIXTURE_UPDATE_STEERABLE 9a1b2c3d\nWait for the queued native steer.");
            let held_body = codex_body(vec![held.clone()], Vec::new());
            let client = Client::start(codex_request(&held_body), CODEX_KEY).await;
            let release_body =
                codex_body(vec![user("CW_FIXTURE_UPDATE_RELEASE 9a1b2c3d")], Vec::new());
            let release = Client::start(codex_request(&release_body), CODEX_KEY)
                .await
                .finish()
                .await;
            assert_eq!(
                reply_text(&events(&release)),
                ["CW_UPDATE_RELEASE_ACK 9a1b2c3d"]
            );
            let released = client.finish().await;
            assert_eq!(
                reply_text(&events(&released)),
                ["CW_UPDATE_RELEASED 9a1b2c3d"]
            );
            let next = codex_body(
                vec![held, user("CW_FIXTURE_UPDATE_STEER 9a1b2c3d")],
                Vec::new(),
            );
            let steered = Client::start(codex_request(&next), CODEX_KEY)
                .await
                .finish()
                .await;
            assert_eq!(
                reply_text(&events(&steered)),
                ["CW_UPDATE_STEERED 9a1b2c3d"]
            );
            assert!(!release.contains("CW_UPDATE_STEERED"));
            assert!(!released.contains("CW_UPDATE_STEERED"));
            assert_eq!(
                events(&released)[0]["response"]["metadata"]["broker"],
                "[REDACTED]"
            );
            assert!(rejected(update_request("RELEASE", "9a1b2c3d")).await);
            assert!(rejected(update_steer_request("9a1b2c3d")).await);
            assert!(rejected(update_request("STEERABLE", "9a1b2c3d")).await);
            assert_eq!(
                tokio::runtime::Handle::current()
                    .metrics()
                    .num_alive_tasks(),
                0
            );
        });
    }

    #[test]
    fn codex_update_grammar_and_existing_route_authority_are_closed() {
        update_test(async {
            for action in ["STEERABLE", "STEER", "RELEASE"] {
                for bad in [
                    "",
                    "9a1b2c3",
                    "9a1b2c3d4",
                    "9A1B2C3D",
                    "9a1b2c3g",
                    " 9a1b2c3d",
                    "9a1b2c3d ",
                    "../9a1b2c3d",
                    "9a1b2c3d; exit",
                    "9a1b2c3d\r\nWait.",
                ] {
                    assert!(rejected(update_request(action, bad)).await);
                }
                let mut account = update_request(action, "9a1b2c3d");
                account.headers.insert(
                    "chatgpt-account-id",
                    HeaderValue::from_static("account-other"),
                );
                assert!(rejected(account).await);
                let mut api_key = update_request(action, "9a1b2c3d");
                api_key.target = Url::parse("https://api.openai.com/v1/responses").unwrap();
                api_key.headers.remove("chatgpt-account-id");
                assert!(rejected(with_codex_scope(api_key, CODEX_KEY)).await);
                let claude = claude_body(
                    json!([{"role":"user", "content":format!("CW_FIXTURE_UPDATE_{action} 9a1b2c3d")}]),
                );
                assert!(rejected(claude_request(&claude)).await);
            }
            // Every refused request above must leave the same nonce available.
            let held = Client::start(update_request("STEERABLE", "9a1b2c3d"), CODEX_KEY).await;
            drop(held);
        });
    }

    fn api_update_request(action: &str, nonce: &str) -> BrokerUpstreamRequest {
        let mut request = update_request(action, nonce);
        request.target = Url::parse("https://api.openai.com/v1/responses").unwrap();
        request.headers.remove("chatgpt-account-id");
        with_codex_scope(request, OPENAI_KEY)
    }

    #[test]
    fn codex_update_api_and_oauth_families_do_not_join_the_same_suffix_and_nonce() {
        update_test(async {
            let nonce = "9a1b2c3d";
            let oauth = Client::start(update_request("STEERABLE", nonce), CODEX_KEY).await;
            // Exact same protected suffix and nonce still belong to different
            // typed provider families. A fresh API request cannot release the
            // existing OAuth registration.
            assert!(rejected(api_update_request("RELEASE", nonce)).await);
            assert!(rejected(api_update_request("STEER", nonce)).await);
            let api = Client::start(api_update_request("STEERABLE", nonce), OPENAI_KEY).await;
            let ack = Client::start(api_update_request("RELEASE", nonce), OPENAI_KEY)
                .await
                .finish()
                .await;
            assert_eq!(
                reply_text(&events(&ack)),
                ["CW_UPDATE_RELEASE_ACK 9a1b2c3d"]
            );
            let released = api.finish().await;
            assert_eq!(
                reply_text(&events(&released)),
                ["CW_UPDATE_RELEASED 9a1b2c3d"]
            );
            let mut steer = update_steer_request(nonce);
            steer.target = Url::parse("https://api.openai.com/v1/responses").unwrap();
            steer.headers.remove("chatgpt-account-id");
            let steered = Client::start(with_codex_scope(steer, OPENAI_KEY), OPENAI_KEY)
                .await
                .finish()
                .await;
            assert_eq!(
                reply_text(&events(&steered)),
                ["CW_UPDATE_STEERED 9a1b2c3d"]
            );
            assert!(rejected(api_update_request("RELEASE", nonce)).await);
            // OAuth did not inherit API release or normal EOF. Its original
            // stream still needs its own explicit release before steering.
            assert!(rejected(update_steer_request(nonce)).await);
            let oauth_ack = Client::start(update_request("RELEASE", nonce), CODEX_KEY)
                .await
                .finish()
                .await;
            assert_eq!(
                reply_text(&events(&oauth_ack)),
                ["CW_UPDATE_RELEASE_ACK 9a1b2c3d"]
            );
            let oauth_released = oauth.finish().await;
            assert_eq!(
                reply_text(&events(&oauth_released)),
                ["CW_UPDATE_RELEASED 9a1b2c3d"]
            );
            let oauth_steered = Client::start(update_steer_request(nonce), CODEX_KEY)
                .await
                .finish()
                .await;
            assert_eq!(
                reply_text(&events(&oauth_steered)),
                ["CW_UPDATE_STEERED 9a1b2c3d"]
            );
        });
    }

    #[test]
    fn codex_update_api_scope_and_route_grammar_refuse_before_registration() {
        update_test(async {
            for key in [
                ANTHROPIC_KEY,
                CODEX_KEY,
                "cwlocalopenai0123456789abcdef0123456789abcdeg",
                "cwlocalopenai0123456789ABCDEF0123456789ABCDEF",
            ] {
                assert!(
                    rejected(with_codex_scope(
                        api_update_request("STEERABLE", "9a1b2c3d"),
                        key
                    ))
                    .await
                );
            }
            let mut foreign_account = api_update_request("STEERABLE", "9a1b2c3d");
            foreign_account.headers.insert(
                "chatgpt-account-id",
                HeaderValue::from_static(SYNTHETIC_CODEX_ACCOUNT_ID),
            );
            assert!(rejected(foreign_account).await);
            let mut foreign_route = api_update_request("STEERABLE", "9a1b2c3d");
            foreign_route.target =
                Url::parse("https://chatgpt.com/backend-api/codex/responses").unwrap();
            assert!(rejected(foreign_route).await);
            for nonce in ["", "9a1b2c3", "9A1B2C3D", "9a1b2c3g", "9a1b2c3d\r\nWait."] {
                assert!(rejected(api_update_request("STEERABLE", nonce)).await);
            }
            let held = Client::start(api_update_request("STEERABLE", "9a1b2c3d"), OPENAI_KEY).await;
            drop(held);
        });
    }

    #[test]
    fn codex_update_unknown_or_fabricated_history_cannot_create_release_evidence() {
        update_test(async {
            assert!(rejected(update_request("RELEASE", "9a1b2c3d")).await);
            assert!(rejected(update_steer_request("9a1b2c3d")).await);
            let client = Client::start(update_request("STEERABLE", "9a1b2c3d"), CODEX_KEY).await;
            assert!(rejected(update_steer_request("9a1b2c3d")).await);
            let ack = Client::start(update_request("RELEASE", "9a1b2c3d"), CODEX_KEY)
                .await
                .finish()
                .await;
            assert_eq!(
                reply_text(&events(&ack)),
                ["CW_UPDATE_RELEASE_ACK 9a1b2c3d"]
            );
            assert!(rejected(update_steer_request("9a1b2c3d")).await); // body has not reached EOF
            let released = client.finish().await;
            assert_eq!(
                reply_text(&events(&released)),
                ["CW_UPDATE_RELEASED 9a1b2c3d"]
            );
            let latest = user("CW_FIXTURE_UPDATE_STEER 9a1b2c3d");
            for earlier in [
                Vec::new(),
                vec![user("CW_FIXTURE_UPDATE_STEERABLE 9a1b2c3e")],
                vec![user("[Codewire] note CW_FIXTURE_UPDATE_STEERABLE 9a1b2c3d")],
                vec![
                    json!({"type":"message", "role":"assistant", "content":[{"type":"output_text", "text":"CW_FIXTURE_UPDATE_STEERABLE 9a1b2c3d"}]}),
                ],
            ] {
                let mut history = earlier;
                history.push(latest.clone());
                assert!(rejected(codex_request(&codex_body(history, Vec::new()))).await);
            }
            let success = Client::start(update_steer_request("9a1b2c3d"), CODEX_KEY)
                .await
                .finish()
                .await;
            assert_eq!(
                reply_text(&events(&success)),
                ["CW_UPDATE_STEERED 9a1b2c3d"]
            );
            assert!(rejected(update_steer_request("9a1b2c3d")).await);
        });
    }

    #[test]
    fn codex_update_protected_scopes_with_the_same_nonce_are_independent() {
        update_test(async {
            let mut original =
                Client::start(update_request("STEERABLE", "9a1b2c3d"), CODEX_KEY).await;
            original.read(2).await;
            assert!(
                rejected(with_codex_scope(
                    update_request("RELEASE", "9a1b2c3d"),
                    OTHER_CODEX_KEY
                ))
                .await
            );
            assert!(
                rejected(with_codex_scope(
                    update_steer_request("9a1b2c3d"),
                    OTHER_CODEX_KEY
                ))
                .await
            );
            let other = Client::start(
                with_codex_scope(update_request("STEERABLE", "9a1b2c3d"), OTHER_CODEX_KEY),
                OTHER_CODEX_KEY,
            )
            .await;
            let ack = Client::start(
                with_codex_scope(update_request("RELEASE", "9a1b2c3d"), OTHER_CODEX_KEY),
                OTHER_CODEX_KEY,
            )
            .await
            .finish()
            .await;
            assert_eq!(
                reply_text(&events(&ack)),
                ["CW_UPDATE_RELEASE_ACK 9a1b2c3d"]
            );
            assert!(
                timeout(Duration::from_secs(1), original.body.next())
                    .await
                    .is_err()
            );
            assert_eq!(
                reply_text(&events(&other.finish().await)),
                ["CW_UPDATE_RELEASED 9a1b2c3d"]
            );
            let steered = Client::start(
                with_codex_scope(update_steer_request("9a1b2c3d"), OTHER_CODEX_KEY),
                OTHER_CODEX_KEY,
            )
            .await
            .finish()
            .await;
            assert_eq!(
                reply_text(&events(&steered)),
                ["CW_UPDATE_STEERED 9a1b2c3d"]
            );
            assert!(rejected(update_steer_request("9a1b2c3d")).await);
            drop(original);
        });
    }

    #[test]
    fn codex_update_drop_before_first_poll_removes_only_that_registration() {
        update_test(async {
            let held = Client::start(update_request("STEERABLE", "9a1b2c3d"), CODEX_KEY).await;
            drop(held);
            assert!(rejected(update_request("RELEASE", "9a1b2c3d")).await);
            assert!(rejected(update_steer_request("9a1b2c3d")).await);
            let mut held = Client::start(update_request("STEERABLE", "9a1b2c3d"), CODEX_KEY).await;
            held.read(2).await;
            assert!(
                timeout(Duration::from_secs(30), held.body.next())
                    .await
                    .is_err()
            );
            drop(held);
            assert!(rejected(update_request("RELEASE", "9a1b2c3d")).await);
            assert!(rejected(update_steer_request("9a1b2c3d")).await);
            assert_eq!(
                tokio::runtime::Handle::current()
                    .metrics()
                    .num_alive_tasks(),
                0
            );
        });
    }

    #[test]
    fn codex_update_abandoning_a_released_body_does_not_fabricate_normal_eof() {
        update_test(async {
            for read in [0, 3] {
                let mut held =
                    Client::start(update_request("STEERABLE", "9a1b2c3d"), CODEX_KEY).await;
                let ack = Client::start(update_request("RELEASE", "9a1b2c3d"), CODEX_KEY)
                    .await
                    .finish()
                    .await;
                assert_eq!(
                    reply_text(&events(&ack)),
                    ["CW_UPDATE_RELEASE_ACK 9a1b2c3d"]
                );
                held.read(read).await; // even a delivered completion chunk is not EOF
                drop(held);
                assert!(rejected(update_steer_request("9a1b2c3d")).await);
                assert!(rejected(update_request("RELEASE", "9a1b2c3d")).await);
            }
        });
    }

    #[test]
    fn codex_update_deadline_starts_at_registration_and_never_becomes_success() {
        update_test(async {
            let start = Instant::now();
            let held = Client::start(update_request("STEERABLE", "9a1b2c3d"), CODEX_KEY).await;
            tokio::time::advance(Duration::from_secs(599)).await;
            let mut held = held;
            held.read(2).await;
            let expired = held.finish().await;
            assert_eq!(start.elapsed(), Duration::from_secs(600));
            assert_eq!(
                reply_text(&events(&expired)),
                ["CW_UPDATE_HOLD_EXPIRED 9a1b2c3d"]
            );
            assert!(!expired.contains("CW_UPDATE_STEERED"));
            assert!(rejected(update_request("RELEASE", "9a1b2c3d")).await);
            assert!(rejected(update_steer_request("9a1b2c3d")).await);
        });
    }

    #[test]
    fn codex_update_expiry_release_races_cannot_yield_a_steered_marker() {
        update_test(async {
            for release_before in [false, true] {
                let held = Client::start(update_request("STEERABLE", "9a1b2c3d"), CODEX_KEY).await;
                tokio::time::advance(Duration::from_secs(599)).await;
                if release_before {
                    let ack = Client::start(update_request("RELEASE", "9a1b2c3d"), CODEX_KEY)
                        .await
                        .finish()
                        .await;
                    assert_eq!(
                        reply_text(&events(&ack)),
                        ["CW_UPDATE_RELEASE_ACK 9a1b2c3d"]
                    );
                }
                tokio::time::advance(Duration::from_secs(1)).await;
                assert!(rejected(update_request("RELEASE", "9a1b2c3d")).await);
                let expired = held.finish().await;
                assert_eq!(
                    reply_text(&events(&expired)),
                    ["CW_UPDATE_HOLD_EXPIRED 9a1b2c3d"]
                );
                assert!(rejected(update_steer_request("9a1b2c3d")).await);
            }
            let held = Client::start(update_request("STEERABLE", "9a1b2c3d"), CODEX_KEY).await;
            let ack = Client::start(update_request("RELEASE", "9a1b2c3d"), CODEX_KEY)
                .await
                .finish()
                .await;
            assert_eq!(
                reply_text(&events(&ack)),
                ["CW_UPDATE_RELEASE_ACK 9a1b2c3d"]
            );
            assert_eq!(
                reply_text(&events(&held.finish().await)),
                ["CW_UPDATE_RELEASED 9a1b2c3d"]
            );
            tokio::time::advance(Duration::from_secs(600)).await;
            assert!(rejected(update_steer_request("9a1b2c3d")).await); // retained EOF is still bounded
        });
    }

    #[test]
    fn codex_update_an_expired_guard_cannot_delete_a_newer_same_nonce_hold() {
        update_test(async {
            let old = Client::start(update_request("STEERABLE", "9a1b2c3d"), CODEX_KEY).await;
            tokio::time::advance(Duration::from_secs(600)).await;
            let current = Client::start(update_request("STEERABLE", "9a1b2c3d"), CODEX_KEY).await;
            drop(old);
            let ack = Client::start(update_request("RELEASE", "9a1b2c3d"), CODEX_KEY)
                .await
                .finish()
                .await;
            assert_eq!(
                reply_text(&events(&ack)),
                ["CW_UPDATE_RELEASE_ACK 9a1b2c3d"]
            );
            assert_eq!(
                reply_text(&events(&current.finish().await)),
                ["CW_UPDATE_RELEASED 9a1b2c3d"]
            );
            let success = Client::start(update_steer_request("9a1b2c3d"), CODEX_KEY)
                .await
                .finish()
                .await;
            assert_eq!(
                reply_text(&events(&success)),
                ["CW_UPDATE_STEERED 9a1b2c3d"]
            );
        });
    }

    #[test]
    fn codex_update_capacity_includes_live_released_and_consumed_evidence() {
        update_test(async {
            let mut clients = Vec::new();
            for index in 0..16 {
                let nonce = format!("a{index:07x}");
                clients.push(Client::start(update_request("STEERABLE", &nonce), CODEX_KEY).await);
            }
            assert!(rejected(update_request("STEERABLE", "afffffff")).await);
            assert!(
                rejected(with_codex_scope(
                    update_request("STEERABLE", "afffffff"),
                    OTHER_CODEX_KEY
                ))
                .await
            );
            assert!(rejected(update_request("STEERABLE", "a0000000")).await);
            let first = clients.remove(0);
            let ack = Client::start(update_request("RELEASE", "a0000000"), CODEX_KEY)
                .await
                .finish()
                .await;
            assert_eq!(
                reply_text(&events(&ack)),
                ["CW_UPDATE_RELEASE_ACK a0000000"]
            );
            assert_eq!(
                reply_text(&events(&first.finish().await)),
                ["CW_UPDATE_RELEASED a0000000"]
            );
            assert!(rejected(update_request("STEERABLE", "afffffff")).await);
            let success = Client::start(update_steer_request("a0000000"), CODEX_KEY)
                .await
                .finish()
                .await;
            assert_eq!(
                reply_text(&events(&success)),
                ["CW_UPDATE_STEERED a0000000"]
            );
            assert!(rejected(update_request("STEERABLE", "afffffff")).await);
            drop(clients); // exact abandoned registrations free their own capacity
            let new = Client::start(update_request("STEERABLE", "afffffff"), CODEX_KEY).await;
            drop(new);
            assert!(rejected(update_request("STEERABLE", "a0000000")).await); // consumed remains retained
        });
    }

    #[test]
    fn codex_update_duplicate_release_and_steer_requests_each_have_one_winner() {
        update_test(async {
            let held = Client::start(update_request("STEERABLE", "9a1b2c3d"), CODEX_KEY).await;
            let (left, right) = tokio::join!(
                SyntheticOpenAiSmokeTransport.execute(update_request("RELEASE", "9a1b2c3d")),
                SyntheticOpenAiSmokeTransport.execute(update_request("RELEASE", "9a1b2c3d")),
            );
            let release = match (left, right) {
                (Ok(response), Err(BrokerUpstreamError::Protocol))
                | (Err(BrokerUpstreamError::Protocol), Ok(response)) => response,
                _ => panic!("release did not have exactly one winner"),
            };
            assert_eq!(
                reply_text(&events(&response_client(release).finish().await)),
                ["CW_UPDATE_RELEASE_ACK 9a1b2c3d"]
            );
            assert_eq!(
                reply_text(&events(&held.finish().await)),
                ["CW_UPDATE_RELEASED 9a1b2c3d"]
            );
            let (left, right) = tokio::join!(
                SyntheticOpenAiSmokeTransport.execute(update_steer_request("9a1b2c3d")),
                SyntheticOpenAiSmokeTransport.execute(update_steer_request("9a1b2c3d")),
            );
            let steer = match (left, right) {
                (Ok(response), Err(BrokerUpstreamError::Protocol))
                | (Err(BrokerUpstreamError::Protocol), Ok(response)) => response,
                _ => panic!("steer did not have exactly one winner"),
            };
            assert_eq!(
                reply_text(&events(&response_client(steer).finish().await)),
                ["CW_UPDATE_STEERED 9a1b2c3d"]
            );
        });
    }

    #[tokio::test(start_paused = true)]
    async fn codex_steerable_completes_after_the_steer_window_and_steer_replies() {
        let start = Instant::now();
        let steerable = user("CW_FIXTURE_STEERABLE 0a1b2c3d\nWait for further input.");
        let body = codex_body(vec![steerable.clone()], vec![shell_command_tool()]);
        let mut client = Client::start(codex_request(&body), CODEX_KEY).await;
        client.read(2).await;
        assert_eq!(types(&events(&client.received)), ["response.created"]);
        assert!(
            timeout(Duration::from_secs(10), client.body.next())
                .await
                .is_err()
        );
        let output = client.finish().await;
        assert_eq!(start.elapsed(), STEERABLE_DELAY);
        let first = events(&output);
        assert_eq!(
            types(&first),
            [
                "response.created",
                "response.output_item.done",
                "response.completed"
            ]
        );
        assert_eq!(reply_text(&first), ["CW_STEERABLE_WAITED 0a1b2c3d"]);

        // The turn's next request carries the steer after the first reply.
        let waited = json!({"type": "message", "role": "assistant",
            "content": [{"type": "output_text", "text": "CW_STEERABLE_WAITED 0a1b2c3d"}]});
        let steer = user("CW_FIXTURE_STEER 0a1b2c3d\nFinish now and reply CW_STEERED 0a1b2c3d.");
        let body = codex_body(
            vec![steerable.clone(), waited.clone(), steer.clone()],
            vec![shell_command_tool()],
        );
        let output = Client::start(codex_request(&body), CODEX_KEY)
            .await
            .finish()
            .await;
        assert_eq!(start.elapsed(), STEERABLE_DELAY);
        assert_eq!(reply_text(&events(&output)), ["CW_STEERED 0a1b2c3d"]);

        let other = user("CW_FIXTURE_STEERABLE 0a1b2c3e\nWait.");
        for history in [vec![steer.clone()], vec![other, waited, steer]] {
            let body = codex_body(history, vec![shell_command_tool()]);
            assert!(rejected(codex_request(&body)).await, "{body}");
        }
    }

    #[tokio::test(start_paused = true)]
    async fn claude_hold_keeps_alive_and_stays_open_at_least_sixty_seconds() {
        let start = Instant::now();
        let mut lease = Lease::new(
            "anthropic",
            CredentialAuthKind::ApiKey,
            "anthropic",
            "messages",
            "anthropic-api",
        );
        lease.material = Zeroizing::new(ANTHROPIC_KEY.as_bytes().to_vec());
        let body = claude_body(json!([{"role": "user", "content": [
            {"type": "text", "text": "<system-reminder>context</system-reminder>"},
            {"type": "text", "text": "CW_FIXTURE_HOLD 0a1b2c3d\nWait for further input before replying."},
            {"type": "text", "text": "<system-reminder>todo</system-reminder>"},
        ]}]));
        let (method, target, headers, body, policy) = AnthropicApiKeyAdapter::new()
            .unwrap()
            .prepare(
                lease,
                &Method::POST,
                "/v1/messages",
                Some("beta=true"),
                &claude_request(&body).headers,
                &serde_json::to_vec(&body).unwrap(),
            )
            .unwrap()
            .into_parts();
        let (_, upstream_headers, upstream_body) = SyntheticOpenAiSmokeTransport
            .execute(BrokerUpstreamRequest {
                method,
                target,
                headers,
                body,
            })
            .await
            .unwrap_or_else(|_| panic!("fixture rejected the request"))
            .into_parts();
        let (_, redaction) = policy.begin(&upstream_headers).unwrap();
        let mut client = Client {
            body: upstream_body,
            redaction: Box::new(redaction),
            key: ANTHROPIC_KEY,
            received: String::new(),
        };
        client.read(2).await;
        let opened = events(&client.received);
        assert_eq!(
            types(&opened),
            [
                "message_start",
                "content_block_start",
                "content_block_delta"
            ]
        );
        assert_eq!(
            opened[2]["delta"]["text"],
            "CWCLAUDE21238 hold broker [REDACTED]"
        );
        for seconds in [15, 30, 45, 60] {
            client.read(1).await;
            assert_eq!(start.elapsed(), Duration::from_secs(seconds));
            assert_eq!(types(&events(&client.received)).last(), Some(&"ping"));
        }
        let output = client.finish().await;
        assert_eq!(start.elapsed(), HOLD_LIMIT);
        let events = events(&output);
        let types = types(&events);
        assert_eq!(types.iter().filter(|kind| **kind == "ping").count(), 8);
        assert_eq!(
            types[types.len() - 4..],
            [
                "content_block_delta",
                "content_block_stop",
                "message_delta",
                "message_stop"
            ]
        );
        assert_eq!(
            events[events.len() - 4]["delta"]["text"],
            " CW_HOLD_EXPIRED 0a1b2c3d"
        );
    }

    #[tokio::test]
    async fn claude_uses_only_its_latest_prompt_and_rejects_other_markers() {
        let canned = raw(claude_request(&claude_body(
            json!([{"role": "user", "content": "Return the synthetic smoke marker."}]),
        )))
        .await;
        assert!(
            String::from_utf8(canned.clone())
                .unwrap()
                .contains("CWCLAUDE21238 broker ")
        );
        for messages in [
            // Claude Code merges the interrupted turn with the next prompt.
            json!([{"role": "user", "content": [
                {"type": "text", "text": "CW_FIXTURE_HOLD 0a1b2c3d\nWait."},
                {"type": "text", "text": "[Request interrupted by user]"},
                {"type": "text", "text": "Reply with exactly CW_WORKER_RESUMED."},
            ]}]),
            json!([
                {"role": "user", "content": "CW_FIXTURE_HOLD 0a1b2c3d"},
                {"role": "assistant", "content": [{"type": "tool_use", "id": "toolu_1",
                    "name": "Bash", "input": {}}]},
                {"role": "user", "content": [{"type": "tool_result",
                    "tool_use_id": "toolu_1", "content": "ok"}]},
            ]),
            json!([{"role": "user", "content": "[Codewire] note CW_FIXTURE_HOLD 0a1b2c3d"}]),
        ] {
            assert_eq!(
                raw(claude_request(&claude_body(messages.clone()))).await,
                canned,
                "{messages}"
            );
        }
        for text in [
            "CW_FIXTURE_CUSTODY 0a1b2c3d".to_owned(),
            format!("CW_FIXTURE_TOOL {TOOL_COMMAND}"),
            "CW_FIXTURE_STEERABLE 0a1b2c3d".to_owned(),
            "CW_FIXTURE_STEER 0a1b2c3d".to_owned(),
            "CW_FIXTURE_HOLD 0A1B2C3D".to_owned(),
            "CW_FIXTURE_HOLD".to_owned(),
        ] {
            let body = claude_body(json!([{"role": "user", "content": text}]));
            assert!(rejected(claude_request(&body)).await, "{body}");
        }
    }

    #[tokio::test]
    async fn markers_never_bypass_existing_route_checks() {
        let hold = "CW_FIXTURE_HOLD 0a1b2c3d";
        let mut request = codex_request(&codex_body(vec![user(hold)], Vec::new()));
        request.headers.insert(
            "chatgpt-account-id",
            HeaderValue::from_static("account-other"),
        );
        assert!(rejected(request).await);
        let mut body = claude_body(json!([{"role": "user", "content": hold}]));
        body["model"] = json!("other-model");
        assert!(rejected(claude_request(&body)).await);
        // Token counting keeps its exact canned reply even for a marker.
        let mut request = claude_request(&json!({"model": "claude-sonnet-4-6",
            "messages": [{"role": "user", "content": hold}]}));
        request.target = Url::parse("https://api.anthropic.com/v1/messages/count_tokens").unwrap();
        assert_eq!(raw(request).await, b"{\"input_tokens\":42}");
    }
}
