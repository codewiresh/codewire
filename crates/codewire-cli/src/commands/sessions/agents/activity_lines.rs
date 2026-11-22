//! The session-log lines a driver writes for what its agent does, and how a
//! Codex turn ends. Moved out of `agents.rs` unchanged (#5897).

use super::*;

/// Session-log lines for what a Claude assistant message does: its text and
/// each tool it calls, with the input that identifies the call.
pub(super) fn claude_activity(value: &Value) -> Vec<String> {
    let Some(Value::Array(blocks)) = value.pointer("/message/content") else {
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
            Some("tool_use") => {
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
                Some(match detail {
                    Some(detail) => format!("tool {name}: {}", preview(detail)),
                    None => format!("tool {name}"),
                })
            }
            _ => None,
        })
        .collect()
}

/// How Codex's `turn/completed` ends the active message (#2982). A refusal
/// the driver interrupted the turn for, or a final error Codex reported, fails
/// a turn that then ends interrupted (with no interrupt a message asked for)
/// or completed with no reply: the provider answered nothing. Every error is
/// a reason [`turn_failure`] made free of credential material.
pub(super) fn codex_turn_outcome(
    params: &Value,
    active: &ActiveTurn,
    model: &str,
    effort: Option<&str>,
) -> (TurnStatus, Option<String>) {
    let native_error = params
        .pointer("/turn/error")
        .filter(|error| !error.is_null())
        .map(|error| turn_failure::codex_failure(error, model, effort));
    let failure = active.failure.clone();
    match params.pointer("/turn/status").and_then(Value::as_str) {
        Some("completed") if active.texts.is_empty() && failure.is_some() => {
            (TurnStatus::Failed, failure)
        }
        Some("completed") => (TurnStatus::Completed, None),
        Some("interrupted") if active.interrupts.is_empty() && failure.is_some() => {
            (TurnStatus::Failed, failure)
        }
        Some("interrupted") => (TurnStatus::Interrupted, native_error),
        Some("failed") => (
            TurnStatus::Failed,
            Some(
                native_error
                    .or(failure)
                    .unwrap_or_else(|| "Codex reported that the turn failed".into()),
            ),
        ),
        other => (
            TurnStatus::Failed,
            Some(format!(
                "Codex ended the turn with unrecognized status {other:?}"
            )),
        ),
    }
}

/// The session-log line for a Codex item. A web search names its query only
/// when it completes; every other item is logged as it starts.
pub(super) fn codex_activity(item: &Value, completed: bool) -> Option<String> {
    let text = |key: &str| item.get(key).and_then(Value::as_str);
    let kind = text("type")?;
    if completed != (kind == "webSearch") {
        return None;
    }
    match kind {
        "commandExecution" => text("command").map(|command| format!("run: {}", preview(command))),
        "fileChange" => {
            let paths: Vec<&str> = item
                .get("changes")?
                .as_array()?
                .iter()
                .filter_map(|change| change.get("path").and_then(Value::as_str))
                .collect();
            Some(format!("edit: {}", preview(&paths.join(" "))))
        }
        "mcpToolCall" => Some(format!(
            "tool {}/{}",
            text("server").unwrap_or("mcp"),
            text("tool").unwrap_or("tool")
        )),
        "dynamicToolCall" => Some(format!("tool {}", text("tool").unwrap_or("tool"))),
        "webSearch" => text("query")
            .filter(|query| !query.trim().is_empty())
            .map(|query| format!("search: {}", preview(query))),
        _ => None,
    }
}
