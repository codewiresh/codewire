//! Structured v1 streaming events emitted by the managed agent driver to its
//! durable session stdout (`\x1eCW_AGENT_V1 {...}\n`).
//!
//! `MessageRecord` and `DriverState` remain the durable source of truth; these
//! lines carry low-latency live deltas and tool activity for attached browsers
//! (`GET /{slug}/{env_id}/_events/agents/{session_id}`) without altering the
//! human-readable `cw agent driver:` lines written to stderr.

use std::io::Write as _;

use serde_json::{Value, json};

use super::preview;

/// Record-separator sentinel that prefixes every v1 structured stream event.
pub(super) const STREAM_EVENT_PREFIX: &str = "\x1eCW_AGENT_V1 ";

/// Maximum UTF-8 bytes emitted in a single `delta` event.
const MAX_DELTA_CHUNK_BYTES: usize = 8 * 1024;

/// Maximum UTF-8 bytes emitted for a tool label or summary.
const MAX_LABEL_BYTES: usize = 240;

#[derive(Debug, PartialEq, Eq)]
pub(super) enum ClaudeStreamEvent {
    Delta(String),
    ToolStart {
        id: String,
        kind: &'static str,
        label: String,
    },
    ToolEnd {
        id: String,
    },
}

#[derive(Debug, PartialEq, Eq)]
pub(super) enum AgyStreamEvent {
    UserInput,
    Delta(String),
    ToolStart {
        id: String,
        kind: &'static str,
        label: String,
    },
    ToolEnd {
        id: String,
        kind: &'static str,
        label: String,
        ok: bool,
        summary: String,
    },
}

fn truncate_str(value: &str, max_bytes: usize) -> String {
    if value.len() <= max_bytes {
        return value.to_owned();
    }
    let mut end = max_bytes;
    while end > 0 && !value.is_char_boundary(end) {
        end -= 1;
    }
    value[..end].to_owned()
}

pub(super) fn format_event_line(payload: &Value) -> Option<String> {
    let serialized = serde_json::to_string(payload).ok()?;
    Some(format!("{STREAM_EVENT_PREFIX}{serialized}"))
}

fn emit(payload: &Value) {
    if let Some(line) = format_event_line(payload) {
        let mut out = std::io::stdout().lock();
        let _ = writeln!(out, "{line}");
        let _ = out.flush();
    }
}

pub(super) fn emit_turn_start(message_id: &str) {
    emit(&json!({
        "v": 1,
        "t": "turn_start",
        "msg": message_id,
    }));
}

pub(super) fn emit_delta(message_id: &str, text: &str) {
    if text.is_empty() {
        return;
    }
    let mut start = 0;
    while start < text.len() {
        let mut end = (start + MAX_DELTA_CHUNK_BYTES).min(text.len());
        while end > start && !text.is_char_boundary(end) {
            end -= 1;
        }
        if end == start {
            break;
        }
        emit(&json!({
            "v": 1,
            "t": "delta",
            "msg": message_id,
            "text": &text[start..end],
        }));
        start = end;
    }
}

pub(super) fn emit_tool_start(message_id: &str, id: &str, kind: &str, label: &str) {
    emit(&json!({
        "v": 1,
        "t": "tool_start",
        "msg": message_id,
        "id": truncate_str(id, 128),
        "kind": truncate_str(kind, 32),
        "label": truncate_str(label, MAX_LABEL_BYTES),
    }));
}

pub(super) fn emit_tool_end(message_id: &str, id: &str, ok: bool, summary: &str) {
    emit(&json!({
        "v": 1,
        "t": "tool_end",
        "msg": message_id,
        "id": truncate_str(id, 128),
        "ok": ok,
        "summary": truncate_str(summary, MAX_LABEL_BYTES),
    }));
}

pub(super) fn emit_turn_end(
    message_id: &str,
    state: &str,
    error: Option<&str>,
    usage: Option<&Value>,
) {
    let mut payload = json!({
        "v": 1,
        "t": "turn_end",
        "msg": message_id,
        "state": state,
    });
    if let Some(error) = error.filter(|e| !e.is_empty()) {
        payload["error"] = json!(truncate_str(error, 1024));
    }
    if let Some(usage) = usage {
        payload["usage"] = usage.clone();
    }
    emit(&payload);
}

/// Extracts a live text delta from Codex `item/agentMessage/delta` params.
pub(super) fn codex_delta(params: &Value) -> Option<&str> {
    params
        .get("delta")
        .and_then(Value::as_str)
        .filter(|delta| !delta.is_empty())
}

/// Extracts `(id, kind, label)` for a Codex tool/activity item.
pub(super) fn codex_tool(item: &Value) -> Option<(String, &'static str, String)> {
    let text = |key: &str| item.get(key).and_then(Value::as_str);
    let item_type = text("type")?;
    let id = text("id")
        .or_else(|| text("callId"))
        .unwrap_or(item_type)
        .to_owned();
    match item_type {
        "commandExecution" => {
            let cmd = text("command").unwrap_or("command");
            Some((id, "run", format!("Ran {}", preview(cmd))))
        }
        "fileChange" => {
            let paths: Vec<&str> = item
                .get("changes")
                .and_then(Value::as_array)
                .map(|changes| {
                    changes
                        .iter()
                        .filter_map(|change| change.get("path").and_then(Value::as_str))
                        .collect()
                })
                .unwrap_or_default();
            let label = if paths.is_empty() {
                "Edited files".to_owned()
            } else {
                format!("Edited {}", preview(&paths.join(", ")))
            };
            Some((id, "edit", label))
        }
        "mcpToolCall" => Some((
            id,
            "tool",
            format!(
                "Called {}/{}",
                text("server").unwrap_or("mcp"),
                text("tool").unwrap_or("tool")
            ),
        )),
        "dynamicToolCall" => Some((
            id,
            "tool",
            format!("Called {}", text("tool").unwrap_or("tool")),
        )),
        "webSearch" => {
            let query = text("query").unwrap_or("");
            let label = if query.trim().is_empty() {
                "Searched web".to_owned()
            } else {
                format!("Searched {}", preview(query))
            };
            Some((id, "search", label))
        }
        _ => None,
    }
}

/// Maps a Claude `stream_event` wrapper (`--include-partial-messages`) to a
/// structured live delta or tool lifecycle event.
pub(super) fn claude_stream_event(value: &Value) -> Option<ClaudeStreamEvent> {
    let event = value.get("event").unwrap_or(value);
    match event.get("type").and_then(Value::as_str)? {
        "content_block_delta" => {
            let delta = event.get("delta")?;
            if delta.get("type").and_then(Value::as_str) == Some("text_delta") {
                let text = delta.get("text").and_then(Value::as_str)?;
                if !text.is_empty() {
                    return Some(ClaudeStreamEvent::Delta(text.to_owned()));
                }
            }
            None
        }
        "content_block_start" => {
            let block = event.get("content_block")?;
            if block.get("type").and_then(Value::as_str) == Some("tool_use") {
                let id = block
                    .get("id")
                    .and_then(Value::as_str)
                    .or_else(|| event.get("index").and_then(Value::as_u64).map(|_| ""))
                    .filter(|s| !s.is_empty())
                    .map(str::to_owned)
                    .unwrap_or_else(|| {
                        format!(
                            "block-{}",
                            event.get("index").and_then(Value::as_u64).unwrap_or(0)
                        )
                    });
                let name = block.get("name").and_then(Value::as_str).unwrap_or("tool");
                let kind = classify_tool_kind(name);
                return Some(ClaudeStreamEvent::ToolStart {
                    id,
                    kind,
                    label: format!("Using {name}"),
                });
            }
            None
        }
        "content_block_stop" => {
            let index = event.get("index").and_then(Value::as_u64)?;
            Some(ClaudeStreamEvent::ToolEnd {
                id: format!("block-{index}"),
            })
        }
        _ => None,
    }
}

/// Extracts `(id, kind, label)` for tool_use blocks inside a completed Claude
/// `assistant` message so tool detail (command/path) is always surfaced.
pub(super) fn claude_assistant_tools(value: &Value) -> Vec<(String, &'static str, String)> {
    let Some(Value::Array(blocks)) = value.pointer("/message/content") else {
        return Vec::new();
    };
    blocks
        .iter()
        .enumerate()
        .filter_map(|(idx, block)| {
            if block.get("type").and_then(Value::as_str) != Some("tool_use") {
                return None;
            }
            let id = block
                .get("id")
                .and_then(Value::as_str)
                .map(str::to_owned)
                .unwrap_or_else(|| format!("block-{idx}"));
            let name = block.get("name").and_then(Value::as_str).unwrap_or("tool");
            let input = block.get("input");
            let detail = [
                "command",
                "file_path",
                "path",
                "pattern",
                "url",
                "query",
                "description",
            ]
            .iter()
            .find_map(|key| input?.get(key)?.as_str());
            let label = match detail {
                Some(detail) => format!("{name}: {}", preview(detail)),
                None => name.to_owned(),
            };
            Some((id, classify_tool_kind(name), label))
        })
        .collect()
}

/// Maps an Antigravity CLI (`agy --output-format stream-json`) `step_update`
/// event to a structured live delta or tool lifecycle event.
pub(super) fn agy_step_update(value: &Value) -> Option<AgyStreamEvent> {
    let step = value.get("step_update").unwrap_or(value);
    let step_type = step.get("step_type").and_then(Value::as_str)?;
    let state = step
        .get("state")
        .and_then(Value::as_str)
        .unwrap_or("ACTIVE");
    let step_index = step.get("step_index").and_then(Value::as_u64).unwrap_or(0);
    match step_type {
        "user_input" => Some(AgyStreamEvent::UserInput),
        "agent_response" => {
            let delta = step
                .get("text_delta")
                .and_then(Value::as_str)
                .filter(|s| !s.is_empty())?;
            Some(AgyStreamEvent::Delta(delta.to_owned()))
        }
        "tool" => {
            let id = format!("step-{step_index}");
            let tool_info = step.get("tool_info");
            let name = step
                .get("tool_name")
                .and_then(Value::as_str)
                .or_else(|| tool_info?.get("name")?.as_str())
                .unwrap_or("tool");
            let params = tool_info.and_then(|info| info.get("parameters"));
            let detail = [
                "CommandLine",
                "command",
                "Path",
                "path",
                "file_path",
                "Query",
                "query",
                "Pattern",
                "pattern",
                "Url",
                "url",
                "toolSummary",
                "description",
            ]
            .iter()
            .find_map(|key| params?.get(key)?.as_str());
            let label = match detail {
                Some(detail) => format!("{name}: {}", preview(detail)),
                None => name.to_owned(),
            };
            let kind = classify_tool_kind(name);
            if state == "DONE" {
                let error = tool_info.and_then(|info| info.get("error"));
                let ok = error.is_none();
                let summary = error
                    .and_then(|err| err.get("message").and_then(Value::as_str))
                    .map(preview)
                    .unwrap_or_else(|| label.clone());
                Some(AgyStreamEvent::ToolEnd {
                    id,
                    kind,
                    label,
                    ok,
                    summary,
                })
            } else {
                Some(AgyStreamEvent::ToolStart { id, kind, label })
            }
        }
        _ if step.get("subagent_info").is_some() => {
            let id = format!("step-{step_index}");
            let role = step
                .pointer("/subagent_info/subagents/0/role")
                .and_then(Value::as_str)
                .or_else(|| {
                    step.pointer("/subagent_info/subagents/0/type_name")
                        .and_then(Value::as_str)
                })
                .unwrap_or("subagent");
            let label = format!("Subagent: {}", preview(role));
            if state == "DONE" {
                Some(AgyStreamEvent::ToolEnd {
                    id,
                    kind: "tool",
                    label: label.clone(),
                    ok: true,
                    summary: label,
                })
            } else {
                Some(AgyStreamEvent::ToolStart {
                    id,
                    kind: "tool",
                    label,
                })
            }
        }
        _ => None,
    }
}

fn classify_tool_kind(name: &str) -> &'static str {
    let lower = name.to_ascii_lowercase();
    if lower.contains("bash")
        || lower.contains("exec")
        || lower.contains("command")
        || lower.contains("run")
    {
        "run"
    } else if lower.contains("read")
        || lower.contains("view")
        || lower.contains("grep")
        || lower.contains("glob")
        || lower.contains("find")
    {
        "read"
    } else if lower.contains("edit") || lower.contains("write") || lower.contains("patch") {
        "edit"
    } else if lower.contains("search") || lower.contains("web") {
        "search"
    } else {
        "tool"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_codex_delta_and_tools() {
        let delta = json!({ "threadId": "t1", "turnId": "u1", "delta": "Hello " });
        assert_eq!(codex_delta(&delta), Some("Hello "));
        assert_eq!(codex_delta(&json!({ "delta": "" })), None);

        let cmd = json!({ "id": "call-1", "type": "commandExecution", "command": "cargo test" });
        assert_eq!(
            codex_tool(&cmd),
            Some(("call-1".into(), "run", "Ran cargo test".into()))
        );

        let edit = json!({
            "id": "call-2",
            "type": "fileChange",
            "changes": [{ "path": "src/main.rs" }, { "path": "Cargo.toml" }]
        });
        assert_eq!(
            codex_tool(&edit),
            Some((
                "call-2".into(),
                "edit",
                "Edited src/main.rs, Cargo.toml".into()
            ))
        );
    }

    #[test]
    fn parses_claude_stream_events_and_assistant_tools() {
        let text_delta = json!({
            "type": "stream_event",
            "event": {
                "type": "content_block_delta",
                "index": 0,
                "delta": { "type": "text_delta", "text": "Checking tests" }
            }
        });
        assert_eq!(
            claude_stream_event(&text_delta),
            Some(ClaudeStreamEvent::Delta("Checking tests".into()))
        );

        let tool_start = json!({
            "type": "stream_event",
            "event": {
                "type": "content_block_start",
                "index": 1,
                "content_block": { "type": "tool_use", "id": "toolu_123", "name": "Bash" }
            }
        });
        assert_eq!(
            claude_stream_event(&tool_start),
            Some(ClaudeStreamEvent::ToolStart {
                id: "toolu_123".into(),
                kind: "run",
                label: "Using Bash".into(),
            })
        );

        let assistant = json!({
            "type": "assistant",
            "message": {
                "content": [
                    { "type": "tool_use", "id": "toolu_123", "name": "Bash", "input": { "command": "cargo test -p web" } }
                ]
            }
        });
        assert_eq!(
            claude_assistant_tools(&assistant),
            vec![("toolu_123".into(), "run", "Bash: cargo test -p web".into())]
        );
    }

    #[test]
    fn parses_agy_step_updates() {
        let user_step = json!({
            "event": "step_update",
            "step_update": {
                "conversation_id": "9ec58bfd-4d67-4f5e-83a5-9d907e9c6b1f",
                "step_index": 0,
                "state": "DONE",
                "step_type": "user_input"
            }
        });
        assert_eq!(agy_step_update(&user_step), Some(AgyStreamEvent::UserInput));

        let delta = json!({
            "event": "step_update",
            "step_update": {
                "step_index": 2,
                "state": "ACTIVE",
                "step_type": "agent_response",
                "text_delta": "Hello from agy"
            }
        });
        assert_eq!(
            agy_step_update(&delta),
            Some(AgyStreamEvent::Delta("Hello from agy".into()))
        );

        let tool_done = json!({
            "event": "step_update",
            "step_update": {
                "step_index": 4,
                "state": "DONE",
                "step_type": "tool",
                "tool_name": "run_command",
                "tool_info": {
                    "name": "run_command",
                    "parameters": { "CommandLine": "cargo test" },
                    "output": "ok\n"
                }
            }
        });
        assert_eq!(
            agy_step_update(&tool_done),
            Some(AgyStreamEvent::ToolEnd {
                id: "step-4".into(),
                kind: "run",
                label: "run_command: cargo test".into(),
                ok: true,
                summary: "run_command: cargo test".into(),
            })
        );
    }

    #[test]
    fn formats_prefixed_single_line_json() {
        let line = format_event_line(&json!({ "v": 1, "t": "delta", "msg": "m1", "text": "a\nb" }))
            .expect("line");
        assert!(line.starts_with(STREAM_EVENT_PREFIX));
        assert!(!line.contains('\n'));
    }
}
