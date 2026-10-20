//! Why a managed agent's turn failed at its provider, as a reason a record
//! may keep and `cw inbox`, `cw wait --message`, `cw logs` and `cw info` may
//! print (#2982).
//!
//! A provider's error text can name more than the failure: a project or
//! organization ID, the broker URL, a trace or request ID, and, in principle,
//! anything a request echoed back. A reason keeps only the refused model or
//! effort, the HTTP status and the class of refusal, plus the provider's own
//! message once every identifier and anything shaped like a key or token is
//! removed. Two refusals get the repair the user needs:
//! - a model the credential cannot use: "this credential cannot use MODEL";
//! - an effort the model does not support: "MODEL does not support effort E".
//!
//! Codewire never retries the task itself. Codex retries a refused request on
//! its own; [`codex_retry_refusal`] lets the driver end that turn at the first
//! refusal instead of waiting through every retry.

use serde_json::Value;

/// A reason is one line of at most this many bytes.
const MAX_REASON_BYTES: usize = 512;
/// A word this long that mixes letters and digits is treated as a secret.
const MIN_OPAQUE_TOKEN_BYTES: usize = 32;
/// Prefixes of provider keys, tokens and identifiers that are never kept.
const SECRET_PREFIXES: [&str; 14] = [
    "sk-",
    "sk_",
    "rk-",
    "pk-",
    "sess-",
    "ghp_",
    "gho_",
    "ghs_",
    "github_pat_",
    "xox",
    "AKIA",
    "eyJ",
    "Bearer",
    "bearer",
];
/// Prefixes of account, project and request identifiers, which name the
/// account behind a credential.
const IDENTIFIER_PREFIXES: [&str; 6] = ["proj_", "org-", "org_", "user-", "req_", "acct_"];
/// Labels Codex appends to a provider error; everything from the first one on
/// is transport detail.
const TRANSPORT_LABELS: [&str; 4] = [", url: ", ", cf-ray: ", ", request id: ", ", request_id: "];

/// What the provider refused.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Refusal {
    /// The credential cannot use this model.
    Model { model: String },
    /// The model does not support this effort.
    Effort {
        model: String,
        effort: String,
        supported: Vec<String>,
    },
    /// Anything else, with the provider's sanitized message.
    Other { message: String },
}

/// The parts of one provider error the reason is built from.
struct ProviderError {
    status: Option<u16>,
    refusal: Refusal,
}

impl ProviderError {
    fn reason(&self, agent: &str) -> String {
        let status = self
            .status
            .map(|status| format!("HTTP {status}"))
            .unwrap_or_default();
        let reason = match &self.refusal {
            Refusal::Model { model } => {
                let detail = if status.is_empty() {
                    "the provider refused the model".to_owned()
                } else {
                    format!("the provider refused the model, {status}")
                };
                let repair = if agent == "codex" {
                    "pass --model (and --effort)"
                } else {
                    "pass --model"
                };
                format!("this credential cannot use {model} ({detail}); {repair}")
            }
            Refusal::Effort {
                model,
                effort,
                supported,
            } => {
                let mut detail = Vec::new();
                if !supported.is_empty() {
                    detail.push(format!("supported: {}", supported.join(", ")));
                }
                if !status.is_empty() {
                    detail.push(status);
                }
                let detail = if detail.is_empty() {
                    String::new()
                } else {
                    format!(" ({})", detail.join("; "))
                };
                format!("{model} does not support effort {effort}{detail}; pass --effort")
            }
            Refusal::Other { message } if status.is_empty() => {
                format!("the provider refused the turn: {message}")
            }
            Refusal::Other { message } => {
                format!("the provider refused the turn ({status}): {message}")
            }
        };
        bounded(&reason)
    }

    fn is_definitive(&self) -> bool {
        matches!(self.refusal, Refusal::Model { .. } | Refusal::Effort { .. })
    }
}

/// The reason for a Codex error object, as `turn/completed`'s `turn.error`
/// and the `error` notification carry it: `message`, `codexErrorInfo` and
/// `additionalDetails`. `model` and `effort` are the launch's, named when the
/// provider's text does not name them.
pub(super) fn codex_failure(error: &Value, model: &str, effort: Option<&str>) -> String {
    match error {
        Value::Object(_) => parse_codex(error, model, effort).reason("codex"),
        Value::String(text) => parse_text(text, None, model, effort).reason("codex"),
        _ => "Codex reported that the turn failed".to_owned(),
    }
}

/// The refusal an `error` notification Codex will retry already settles: the
/// credential cannot use the model, or the model does not support the
/// effort. Retrying cannot change either, so the driver ends the turn at the
/// first one. `None` for anything that may still succeed, such as a dropped
/// stream or a rate limit, and for an error Codex will not retry.
pub(super) fn codex_retry_refusal(
    params: &Value,
    model: &str,
    effort: Option<&str>,
) -> Option<String> {
    if params.get("willRetry").and_then(Value::as_bool) != Some(true) {
        return None;
    }
    let error = params.get("error")?;
    let parsed = parse_codex(error, model, effort);
    parsed.is_definitive().then(|| parsed.reason("codex"))
}

/// The reason for a Claude turn that ended with an error: its result
/// subtype and the text Claude reported, which for a provider refusal names
/// the API status and the provider's body.
pub(super) fn claude_failure(subtype: &str, detail: &str, model: &str) -> String {
    if let Some(refused) = claude_model_refusal(detail) {
        return ProviderError {
            status: http_status_in(detail),
            refusal: Refusal::Model {
                model: if refused.is_empty() {
                    model.to_owned()
                } else {
                    refused
                },
            },
        }
        .reason("claude");
    }
    let detail = sanitize(&json_error_message(detail).unwrap_or_else(|| detail.to_owned()));
    let reason = if subtype == "success" {
        format!("Claude's turn failed: {detail}")
    } else {
        format!("Claude ended the turn with {subtype}: {detail}")
    };
    bounded(&reason)
}

/// `text` with every identifier, URL and secret-shaped word removed, on one
/// line of at most [`MAX_REASON_BYTES`] bytes. For text that names no
/// provider error, such as a JSON-RPC refusal from the agent itself.
pub(super) fn sanitize(text: &str) -> String {
    let mut text = text.split_whitespace().collect::<Vec<_>>().join(" ");
    if let Some(cut) = TRANSPORT_LABELS
        .iter()
        .filter_map(|label| text.find(label))
        .min()
    {
        text.truncate(cut);
    }
    let mut words = Vec::new();
    let mut redact_next = false;
    for word in text.split(' ') {
        let core = word.trim_matches(|c: char| !c.is_ascii_alphanumeric() && c != '_' && c != '-');
        if redact_next {
            redact_next = false;
            words.push("[redacted]".to_owned());
            continue;
        }
        if core.eq_ignore_ascii_case("bearer") {
            redact_next = true;
            words.push(word.to_owned());
            continue;
        }
        if word.contains("://") {
            words.push("[url]".to_owned());
        } else if is_secret(core) {
            words.push("[redacted]".to_owned());
        } else if IDENTIFIER_PREFIXES
            .iter()
            .any(|prefix| core.starts_with(prefix))
        {
            words.push("[id]".to_owned());
        } else {
            words.push(word.to_owned());
        }
    }
    bounded(&words.join(" "))
}

fn bounded(text: &str) -> String {
    let (text, truncated) = super::truncate_utf8(text.trim(), MAX_REASON_BYTES);
    if truncated {
        format!("{text}…")
    } else {
        text
    }
}

fn is_secret(word: &str) -> bool {
    if SECRET_PREFIXES
        .iter()
        .any(|prefix| word.len() >= prefix.len() + 6 && word.starts_with(prefix))
    {
        return true;
    }
    word.len() >= MIN_OPAQUE_TOKEN_BYTES
        && word.bytes().any(|b| b.is_ascii_digit())
        && word.bytes().any(|b| b.is_ascii_alphabetic())
}

fn parse_codex(error: &Value, model: &str, effort: Option<&str>) -> ProviderError {
    let message = error.get("message").and_then(Value::as_str).unwrap_or("");
    let details = error.get("additionalDetails").and_then(Value::as_str);
    // A retried error's message is Codex's own progress ("Reconnecting...
    // 1/5"); the provider's text is in its details.
    let text = match details {
        Some(details) if !details.trim().is_empty() => details,
        _ => message,
    };
    let status = error.get("codexErrorInfo").and_then(http_status_field);
    parse_text(text, status, model, effort)
}

/// `httpStatusCode` anywhere in Codex's `codexErrorInfo`, whose variant
/// (`httpConnectionFailed`, `responseStreamDisconnected`, ...) names the
/// transport rather than the refusal.
fn http_status_field(info: &Value) -> Option<u16> {
    match info {
        Value::Object(map) => map
            .get("httpStatusCode")
            .and_then(Value::as_u64)
            .and_then(|status| u16::try_from(status).ok())
            .or_else(|| map.values().find_map(http_status_field)),
        _ => None,
    }
}

fn parse_text(text: &str, status: Option<u16>, model: &str, effort: Option<&str>) -> ProviderError {
    let status = status.or_else(|| http_status_in(text));
    let body = json_error(text);
    let message = body
        .as_ref()
        .and_then(|body| body.message.clone())
        .unwrap_or_else(|| text.to_owned());
    let code = body.as_ref().and_then(|body| body.code.as_deref());
    let param = body.as_ref().and_then(|body| body.param.as_deref());

    if code == Some("model_not_found")
        || message.contains("does not have access to model")
        || (message.contains("model") && message.contains("does not exist"))
    {
        let refused = quoted_after(&message, "model `")
            .or_else(|| quoted_after(&message, "model '"))
            .or_else(|| quoted_after(&message, "The model `"))
            .filter(|refused| valid_name(refused))
            .unwrap_or_else(|| model.to_owned());
        return ProviderError {
            status,
            refusal: Refusal::Model { model: refused },
        };
    }
    if param == Some("reasoning.effort")
        || (message.contains("Unsupported value: '")
            && message.contains("is not supported with the '"))
    {
        let refused_effort = quoted_after(&message, "Unsupported value: '")
            .filter(|value| valid_name(value))
            .or_else(|| effort.map(str::to_owned))
            .unwrap_or_else(|| "(default)".to_owned());
        let refused_model = quoted_after(&message, "with the '")
            .filter(|value| valid_name(value))
            .unwrap_or_else(|| model.to_owned());
        let supported = message
            .split_once("Supported values are:")
            .map(|(_, list)| {
                list.split('\'')
                    .skip(1)
                    .step_by(2)
                    .filter(|value| valid_name(value))
                    .map(str::to_owned)
                    .collect()
            })
            .unwrap_or_default();
        return ProviderError {
            status,
            refusal: Refusal::Effort {
                model: refused_model,
                effort: refused_effort,
                supported,
            },
        };
    }
    // Codex's own prefix repeats the status the reason already names.
    let message = strip_status_prefix(&message);
    ProviderError {
        status,
        refusal: Refusal::Other {
            message: sanitize(message),
        },
    }
}

struct JsonError {
    message: Option<String>,
    code: Option<String>,
    param: Option<String>,
}

/// The provider's JSON error body, `{"error": {"message", "code", "param"}}`,
/// when `text` is one, alone or after Codex's "unexpected status ...: "
/// prefix.
fn json_error(text: &str) -> Option<JsonError> {
    let start = text.find('{')?;
    let value: Value = serde_json::from_str(text[start..].trim()).ok()?;
    let error = value.get("error").filter(|error| error.is_object())?;
    let field = |key: &str| error.get(key).and_then(Value::as_str).map(str::to_owned);
    Some(JsonError {
        message: field("message"),
        code: field("code"),
        param: field("param"),
    })
}

fn json_error_message(text: &str) -> Option<String> {
    let prefix = text
        .find('{')
        .map(|start| text[..start].trim().to_owned())?;
    let message = json_error(text)?.message?;
    Some(if prefix.is_empty() {
        message
    } else {
        format!("{prefix} {message}")
    })
}

/// "unexpected status 403 Forbidden: ..." or "API Error: 404 ...".
fn http_status_in(text: &str) -> Option<u16> {
    ["unexpected status ", "API Error: ", "status code "]
        .iter()
        .find_map(|marker| {
            let rest = &text[text.find(marker)? + marker.len()..];
            let digits: String = rest.chars().take_while(char::is_ascii_digit).collect();
            digits
                .parse::<u16>()
                .ok()
                .filter(|status| (100..600).contains(status))
        })
}

fn strip_status_prefix(text: &str) -> &str {
    match text.strip_prefix("unexpected status ") {
        Some(rest) => rest.split_once(": ").map_or(text, |(_, message)| message),
        None => text,
    }
}

/// The text between `marker` and the next copy of the quote it ends with.
fn quoted_after(text: &str, marker: &str) -> Option<String> {
    let quote = marker.chars().last()?;
    let start = text.find(marker)? + marker.len();
    let end = text[start..].find(quote)?;
    Some(text[start..start + end].to_owned())
}

/// A model or effort name a reason may repeat: short, with no spaces or
/// characters that could carry anything else.
fn valid_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-._:/@".contains(&b))
        && !is_secret(value)
}

/// The model a Claude provider refusal names: Anthropic's `not_found_error`
/// body ("model: NAME") or Claude Code's own message for it ("There's an
/// issue with the selected model (NAME)"). `Some("")` when it names none.
fn claude_model_refusal(detail: &str) -> Option<String> {
    let named = |marker: &str, end: char| {
        let start = detail.find(marker)? + marker.len();
        let rest = &detail[start..];
        let name: String = rest
            .chars()
            .take_while(|c| *c != end && *c != '"')
            .collect();
        Some(name.trim().to_owned())
    };
    if detail.contains("not_found_error") && detail.contains("model:") {
        return Some(
            named("model:", '"')
                .filter(|name| valid_name(name))
                .unwrap_or_default(),
        );
    }
    if detail.contains("issue with the selected model") {
        return Some(
            named("issue with the selected model (", ')')
                .filter(|name| valid_name(name))
                .unwrap_or_default(),
        );
    }
    None
}

#[cfg(test)]
#[path = "turn_failure_tests.rs"]
mod tests;
