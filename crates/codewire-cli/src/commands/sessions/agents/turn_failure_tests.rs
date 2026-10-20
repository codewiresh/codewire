//! Tests for [`super`] with Codex app-server event sequences recorded from
//! Codex 0.160.0, the version the workspace image pins (#2982). Each was
//! recorded by driving `codex app-server` over stdio with the managed
//! driver's own `thread/start` and `turn/start` parameters, against a
//! loopback fake of the OpenAI Responses API that answered with OpenAI's own
//! refusal bodies; no provider was called and no credential existed. The
//! project ID is synthetic, the loopback port is normalized to the managed
//! route's 38081, timestamps to 0, and only Codex's own lines are kept.

use super::*;
use crate::commands::sessions::agents::{
    ActiveTurn, AgentBinding, AgentCapabilities, AgentConfig, AgentKind, AgentStore as _, Driver,
    DriverEnvironment, DriverPhase, DriverState, MessageAction, MessageRecord, MessageState,
    NativeLine, Peer, create_message, load_message, now, read_native_stdout, update_message,
};
use serde_json::json;
use std::collections::{HashMap, HashSet, VecDeque};
use std::path::PathBuf;
use std::process::Stdio;
use std::time::Duration;

/// A key whose project may not use the model: five retries Codex reports with `willRetry`, then the turn fails.
pub(super) const MODEL_REFUSED: &str = r##"
{"id":3,"result":{"turn":{"id":"01a159b5-7526-7c43-81bc-96c6895abafe","items":[],"itemsView":"notLoaded","status":"inProgress","error":null,"startedAt":null,"completedAt":null,"durationMs":null}}}
{"method":"thread/status/changed","params":{"threadId":"01a159b5-7503-72e2-919b-8bbf0172ca10","status":{"type":"active","activeFlags":[]}},"emittedAtMs":0}
{"method":"turn/started","params":{"threadId":"01a159b5-7503-72e2-919b-8bbf0172ca10","turn":{"id":"01a159b5-7526-7c43-81bc-96c6895abafe","items":[],"itemsView":"notLoaded","status":"inProgress","error":null,"startedAt":1792506426,"completedAt":null,"durationMs":null}},"emittedAtMs":0}
{"method":"item/started","params":{"item":{"type":"userMessage","id":"01a159b5-7595-72e3-a8b8-0ca1aa3bd5f6","clientId":null,"content":[{"type":"text","text":"Reply with exactly CW2982_OK.","text_elements":[]}]},"threadId":"01a159b5-7503-72e2-919b-8bbf0172ca10","turnId":"01a159b5-7526-7c43-81bc-96c6895abafe","startedAtMs":1792506426774},"emittedAtMs":0}
{"method":"item/completed","params":{"item":{"type":"userMessage","id":"01a159b5-7595-72e3-a8b8-0ca1aa3bd5f6","clientId":null,"content":[{"type":"text","text":"Reply with exactly CW2982_OK.","text_elements":[]}]},"threadId":"01a159b5-7503-72e2-919b-8bbf0172ca10","turnId":"01a159b5-7526-7c43-81bc-96c6895abafe","completedAtMs":1792506426774},"emittedAtMs":0}
{"method":"error","params":{"error":{"message":"Reconnecting... 1/5","codexErrorInfo":{"responseStreamDisconnected":{"httpStatusCode":403}},"additionalDetails":"unexpected status 403 Forbidden: Project `proj_SYNTHETIC0000` does not have access to model `gpt-6.1-sol`, url: http://127.0.0.1:38081/v1/responses, cf-ray: synthetic0000-AMS, request id: req_synthetic0000","misalignment":null},"willRetry":true,"threadId":"01a159b5-7503-72e2-919b-8bbf0172ca10","turnId":"01a159b5-7526-7c43-81bc-96c6895abafe"},"emittedAtMs":0}
{"method":"error","params":{"error":{"message":"Reconnecting... 2/5","codexErrorInfo":{"responseStreamDisconnected":{"httpStatusCode":403}},"additionalDetails":"unexpected status 403 Forbidden: Project `proj_SYNTHETIC0000` does not have access to model `gpt-6.1-sol`, url: http://127.0.0.1:38081/v1/responses, cf-ray: synthetic0000-AMS, request id: req_synthetic0000","misalignment":null},"willRetry":true,"threadId":"01a159b5-7503-72e2-919b-8bbf0172ca10","turnId":"01a159b5-7526-7c43-81bc-96c6895abafe"},"emittedAtMs":0}
{"method":"error","params":{"error":{"message":"Reconnecting... 3/5","codexErrorInfo":{"responseStreamDisconnected":{"httpStatusCode":403}},"additionalDetails":"unexpected status 403 Forbidden: Project `proj_SYNTHETIC0000` does not have access to model `gpt-6.1-sol`, url: http://127.0.0.1:38081/v1/responses, cf-ray: synthetic0000-AMS, request id: req_synthetic0000","misalignment":null},"willRetry":true,"threadId":"01a159b5-7503-72e2-919b-8bbf0172ca10","turnId":"01a159b5-7526-7c43-81bc-96c6895abafe"},"emittedAtMs":0}
{"method":"error","params":{"error":{"message":"Reconnecting... 4/5","codexErrorInfo":{"responseStreamDisconnected":{"httpStatusCode":403}},"additionalDetails":"unexpected status 403 Forbidden: Project `proj_SYNTHETIC0000` does not have access to model `gpt-6.1-sol`, url: http://127.0.0.1:38081/v1/responses, cf-ray: synthetic0000-AMS, request id: req_synthetic0000","misalignment":null},"willRetry":true,"threadId":"01a159b5-7503-72e2-919b-8bbf0172ca10","turnId":"01a159b5-7526-7c43-81bc-96c6895abafe"},"emittedAtMs":0}
{"method":"error","params":{"error":{"message":"Reconnecting... 5/5","codexErrorInfo":{"responseStreamDisconnected":{"httpStatusCode":403}},"additionalDetails":"unexpected status 403 Forbidden: Project `proj_SYNTHETIC0000` does not have access to model `gpt-6.1-sol`, url: http://127.0.0.1:38081/v1/responses, cf-ray: synthetic0000-AMS, request id: req_synthetic0000","misalignment":null},"willRetry":true,"threadId":"01a159b5-7503-72e2-919b-8bbf0172ca10","turnId":"01a159b5-7526-7c43-81bc-96c6895abafe"},"emittedAtMs":0}
{"method":"thread/status/changed","params":{"threadId":"01a159b5-7503-72e2-919b-8bbf0172ca10","status":{"type":"systemError"}},"emittedAtMs":0}
{"method":"error","params":{"error":{"message":"unexpected status 403 Forbidden: Project `proj_SYNTHETIC0000` does not have access to model `gpt-6.1-sol`, url: http://127.0.0.1:38081/v1/responses, cf-ray: synthetic0000-AMS, request id: req_synthetic0000","codexErrorInfo":{"httpConnectionFailed":{"httpStatusCode":403}},"additionalDetails":null,"misalignment":null},"willRetry":false,"threadId":"01a159b5-7503-72e2-919b-8bbf0172ca10","turnId":"01a159b5-7526-7c43-81bc-96c6895abafe"},"emittedAtMs":0}
{"method":"turn/completed","params":{"threadId":"01a159b5-7503-72e2-919b-8bbf0172ca10","turn":{"id":"01a159b5-7526-7c43-81bc-96c6895abafe","items":[],"itemsView":"notLoaded","status":"failed","error":{"message":"unexpected status 403 Forbidden: Project `proj_SYNTHETIC0000` does not have access to model `gpt-6.1-sol`, url: http://127.0.0.1:38081/v1/responses, cf-ray: synthetic0000-AMS, request id: req_synthetic0000","codexErrorInfo":{"httpConnectionFailed":{"httpStatusCode":403}},"additionalDetails":null,"misalignment":null},"startedAt":1792506426,"completedAt":1792506433,"durationMs":7048}},"emittedAtMs":0}
"##;

/// The same refusal when the client sends `turn/interrupt` at the first retry: one provider request, and the turn ends interrupted with no error.
pub(super) const MODEL_REFUSED_INTERRUPTED: &str = r##"
{"id":3,"result":{"turn":{"id":"01a159bc-46f2-7bb0-a89c-7df4276b29a0","items":[],"itemsView":"notLoaded","status":"inProgress","error":null,"startedAt":null,"completedAt":null,"durationMs":null}}}
{"method":"thread/status/changed","params":{"threadId":"01a159bc-46e8-7802-ba14-b3328cef8ef6","status":{"type":"active","activeFlags":[]}},"emittedAtMs":0}
{"method":"turn/started","params":{"threadId":"01a159bc-46e8-7802-ba14-b3328cef8ef6","turn":{"id":"01a159bc-46f2-7bb0-a89c-7df4276b29a0","items":[],"itemsView":"notLoaded","status":"inProgress","error":null,"startedAt":1792506873,"completedAt":null,"durationMs":null}},"emittedAtMs":0}
{"method":"item/started","params":{"item":{"type":"userMessage","id":"01a159bc-4707-7d51-b012-3bafe03a9242","clientId":null,"content":[{"type":"text","text":"Reply with exactly CW2982_OK.","text_elements":[]}]},"threadId":"01a159bc-46e8-7802-ba14-b3328cef8ef6","turnId":"01a159bc-46f2-7bb0-a89c-7df4276b29a0","startedAtMs":1792506873608},"emittedAtMs":0}
{"method":"item/completed","params":{"item":{"type":"userMessage","id":"01a159bc-4707-7d51-b012-3bafe03a9242","clientId":null,"content":[{"type":"text","text":"Reply with exactly CW2982_OK.","text_elements":[]}]},"threadId":"01a159bc-46e8-7802-ba14-b3328cef8ef6","turnId":"01a159bc-46f2-7bb0-a89c-7df4276b29a0","completedAtMs":1792506873608},"emittedAtMs":0}
{"method":"error","params":{"error":{"message":"Reconnecting... 1/5","codexErrorInfo":{"responseStreamDisconnected":{"httpStatusCode":403}},"additionalDetails":"unexpected status 403 Forbidden: Project `proj_SYNTHETIC0000` does not have access to model `gpt-6.1-sol`, url: http://127.0.0.1:38081/v1/responses, cf-ray: synthetic0000-AMS, request id: req_synthetic0000","misalignment":null},"willRetry":true,"threadId":"01a159bc-46e8-7802-ba14-b3328cef8ef6","turnId":"01a159bc-46f2-7bb0-a89c-7df4276b29a0"},"emittedAtMs":0}
{"id":4,"result":{}}
{"method":"thread/status/changed","params":{"threadId":"01a159bc-46e8-7802-ba14-b3328cef8ef6","status":{"type":"idle"}},"emittedAtMs":0}
{"method":"turn/completed","params":{"threadId":"01a159bc-46e8-7802-ba14-b3328cef8ef6","turn":{"id":"01a159bc-46f2-7bb0-a89c-7df4276b29a0","items":[],"itemsView":"notLoaded","status":"interrupted","error":null,"startedAt":1792506873,"completedAt":1792506873,"durationMs":41}},"emittedAtMs":0}
"##;

/// `--model gpt-5.3-codex --effort max`: the provider refuses the effort at once and Codex does not retry.
pub(super) const EFFORT_REFUSED: &str = r##"
{"method":"warning","params":{"threadId":"01a159b5-a4e8-7c62-81ed-1a6c6dec8c9a","message":"Model metadata for `gpt-5.3-codex` not found. Defaulting to fallback metadata; this can degrade performance and cause issues."},"emittedAtMs":0}
{"id":3,"result":{"turn":{"id":"01a159b5-a4fe-74d3-9c97-9b3d40aaaca4","items":[],"itemsView":"notLoaded","status":"inProgress","error":null,"startedAt":null,"completedAt":null,"durationMs":null}}}
{"method":"thread/status/changed","params":{"threadId":"01a159b5-a4e8-7c62-81ed-1a6c6dec8c9a","status":{"type":"active","activeFlags":[]}},"emittedAtMs":0}
{"method":"turn/started","params":{"threadId":"01a159b5-a4e8-7c62-81ed-1a6c6dec8c9a","turn":{"id":"01a159b5-a4fe-74d3-9c97-9b3d40aaaca4","items":[],"itemsView":"notLoaded","status":"inProgress","error":null,"startedAt":1792506438,"completedAt":null,"durationMs":null}},"emittedAtMs":0}
{"method":"item/started","params":{"item":{"type":"userMessage","id":"01a159b5-a549-7392-a156-6b028a26d208","clientId":null,"content":[{"type":"text","text":"Reply with exactly CW2982_OK.","text_elements":[]}]},"threadId":"01a159b5-a4e8-7c62-81ed-1a6c6dec8c9a","turnId":"01a159b5-a4fe-74d3-9c97-9b3d40aaaca4","startedAtMs":1792506438986},"emittedAtMs":0}
{"method":"item/completed","params":{"item":{"type":"userMessage","id":"01a159b5-a549-7392-a156-6b028a26d208","clientId":null,"content":[{"type":"text","text":"Reply with exactly CW2982_OK.","text_elements":[]}]},"threadId":"01a159b5-a4e8-7c62-81ed-1a6c6dec8c9a","turnId":"01a159b5-a4fe-74d3-9c97-9b3d40aaaca4","completedAtMs":1792506438986},"emittedAtMs":0}
{"method":"thread/status/changed","params":{"threadId":"01a159b5-a4e8-7c62-81ed-1a6c6dec8c9a","status":{"type":"systemError"}},"emittedAtMs":0}
{"method":"error","params":{"error":{"message":"{\n  \"error\": {\n    \"message\": \"Unsupported value: 'max' is not supported with the 'gpt-5.3-codex' model. Supported values are: 'none', 'low', 'medium', 'high', and 'xhigh'.\",\n    \"type\": \"invalid_request_error\",\n    \"param\": \"reasoning.effort\",\n    \"code\": \"unsupported_value\"\n  }\n}","codexErrorInfo":"other","additionalDetails":null,"misalignment":null},"willRetry":false,"threadId":"01a159b5-a4e8-7c62-81ed-1a6c6dec8c9a","turnId":"01a159b5-a4fe-74d3-9c97-9b3d40aaaca4"},"emittedAtMs":0}
{"method":"turn/completed","params":{"threadId":"01a159b5-a4e8-7c62-81ed-1a6c6dec8c9a","turn":{"id":"01a159b5-a4fe-74d3-9c97-9b3d40aaaca4","items":[],"itemsView":"notLoaded","status":"failed","error":{"message":"{\n  \"error\": {\n    \"message\": \"Unsupported value: 'max' is not supported with the 'gpt-5.3-codex' model. Supported values are: 'none', 'low', 'medium', 'high', and 'xhigh'.\",\n    \"type\": \"invalid_request_error\",\n    \"param\": \"reasoning.effort\",\n    \"code\": \"unsupported_value\"\n  }\n}","codexErrorInfo":"other","additionalDetails":null,"misalignment":null},"startedAt":1792506438,"completedAt":1792506439,"durationMs":186}},"emittedAtMs":0}
"##;

/// `--model gpt-6.1-sol --effort medium` against a provider that answers: the turn completes with the agent's message.
pub(super) const COMPLETED: &str = r##"
{"id":3,"result":{"turn":{"id":"01a159bc-10c0-7f91-87b7-82eecb96d674","items":[],"itemsView":"notLoaded","status":"inProgress","error":null,"startedAt":null,"completedAt":null,"durationMs":null}}}
{"method":"thread/status/changed","params":{"threadId":"01a159bc-10b4-7661-8a38-06c82a8d2835","status":{"type":"active","activeFlags":[]}},"emittedAtMs":0}
{"method":"turn/started","params":{"threadId":"01a159bc-10b4-7661-8a38-06c82a8d2835","turn":{"id":"01a159bc-10c0-7f91-87b7-82eecb96d674","items":[],"itemsView":"notLoaded","status":"inProgress","error":null,"startedAt":1792506859,"completedAt":null,"durationMs":null}},"emittedAtMs":0}
{"method":"item/started","params":{"item":{"type":"userMessage","id":"01a159bc-10de-7570-9a19-d89bce006043","clientId":null,"content":[{"type":"text","text":"Reply with exactly CW2982_OK.","text_elements":[]}]},"threadId":"01a159bc-10b4-7661-8a38-06c82a8d2835","turnId":"01a159bc-10c0-7f91-87b7-82eecb96d674","startedAtMs":1792506859742},"emittedAtMs":0}
{"method":"item/completed","params":{"item":{"type":"userMessage","id":"01a159bc-10de-7570-9a19-d89bce006043","clientId":null,"content":[{"type":"text","text":"Reply with exactly CW2982_OK.","text_elements":[]}]},"threadId":"01a159bc-10b4-7661-8a38-06c82a8d2835","turnId":"01a159bc-10c0-7f91-87b7-82eecb96d674","completedAtMs":1792506859742},"emittedAtMs":0}
{"method":"item/started","params":{"item":{"type":"agentMessage","id":"msg_synthetic","text":"CW2982_OK","phase":null,"memoryCitation":null,"delivery":null,"questions":null},"threadId":"01a159bc-10b4-7661-8a38-06c82a8d2835","turnId":"01a159bc-10c0-7f91-87b7-82eecb96d674","startedAtMs":1792506859756},"emittedAtMs":0}
{"method":"item/completed","params":{"item":{"type":"agentMessage","id":"msg_synthetic","text":"CW2982_OK","phase":null,"memoryCitation":null,"delivery":null,"questions":null},"threadId":"01a159bc-10b4-7661-8a38-06c82a8d2835","turnId":"01a159bc-10c0-7f91-87b7-82eecb96d674","completedAtMs":1792506859756},"emittedAtMs":0}
{"method":"thread/tokenUsage/updated","params":{"threadId":"01a159bc-10b4-7661-8a38-06c82a8d2835","turnId":"01a159bc-10c0-7f91-87b7-82eecb96d674","tokenUsage":{"total":{"totalTokens":12,"inputTokens":10,"cachedInputTokens":0,"cacheWriteInputTokens":0,"outputTokens":2,"reasoningOutputTokens":0},"last":{"totalTokens":12,"inputTokens":10,"cachedInputTokens":0,"cacheWriteInputTokens":0,"outputTokens":2,"reasoningOutputTokens":0},"modelContextWindow":258400}},"emittedAtMs":0}
{"method":"account/rateLimits/updated","params":{"rateLimits":{"limitId":"codex","limitName":null,"normalModelSlug":null,"primary":null,"secondary":null,"credits":null,"individualLimit":null,"spendControlReached":null,"planType":null,"rateLimitReachedType":null}},"emittedAtMs":0}
{"method":"thread/status/changed","params":{"threadId":"01a159bc-10b4-7661-8a38-06c82a8d2835","status":{"type":"idle"}},"emittedAtMs":0}
{"method":"turn/completed","params":{"threadId":"01a159bc-10b4-7661-8a38-06c82a8d2835","turn":{"id":"01a159bc-10c0-7f91-87b7-82eecb96d674","items":[{"type":"agentMessage","id":"msg_synthetic","text":"CW2982_OK","phase":null,"memoryCitation":null,"delivery":null,"questions":null}],"itemsView":"summary","status":"completed","error":null,"startedAt":1792506859,"completedAt":1792506859,"durationMs":45}},"emittedAtMs":0}
"##;

const MODEL_REASON: &str = "this credential cannot use gpt-6.1-sol (the provider refused the model, HTTP 403); pass --model (and --effort)";
const EFFORT_REASON: &str = "gpt-5.3-codex does not support effort max (supported: none, low, medium, high, xhigh); pass --effort";

fn lines(fixture: &str) -> Vec<Value> {
    fixture
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str(line).unwrap())
        .collect()
}

fn method<'a>(fixture: &'a [Value], name: &str) -> Vec<&'a Value> {
    fixture
        .iter()
        .filter(|line| line.get("method").and_then(Value::as_str) == Some(name))
        .map(|line| &line["params"])
        .collect()
}

/// Nothing a reason keeps can name the account, the route or a request.
fn assert_credential_free(reason: &str) {
    for leaked in [
        "proj_",
        "SYNTHETIC0000",
        "127.0.0.1",
        "38081",
        "req_",
        "cf-ray",
        "http",
    ] {
        assert!(!reason.contains(leaked), "{leaked} in {reason}");
    }
}

#[test]
fn a_recorded_model_refusal_reads_as_the_model_the_credential_cannot_use() {
    let fixture = lines(MODEL_REFUSED);
    let errors = method(&fixture, "error");
    assert_eq!(errors.len(), 6, "five retries and the final error");
    // Each retry already names the refusal, so the driver ends the turn at
    // the first; nothing Codex reports later changes the reason.
    for retry in &errors[..5] {
        assert_eq!(retry["willRetry"], true);
        assert_eq!(
            codex_retry_refusal(retry, "gpt-6.1-sol", Some("medium")).as_deref(),
            Some(MODEL_REASON)
        );
    }
    assert_eq!(errors[5]["willRetry"], false);
    assert_eq!(
        codex_retry_refusal(errors[5], "gpt-6.1-sol", Some("medium")),
        None
    );
    assert_eq!(
        codex_failure(&errors[5]["error"], "gpt-6.1-sol", Some("medium")),
        MODEL_REASON
    );
    let completed = method(&fixture, "turn/completed");
    assert_eq!(completed[0]["turn"]["status"], "failed");
    let reason = codex_failure(
        &completed[0]["turn"]["error"],
        "gpt-6.1-sol",
        Some("medium"),
    );
    assert_eq!(reason, MODEL_REASON);
    assert_credential_free(&reason);
    // The model comes from the provider's text, not the launch.
    assert_eq!(
        codex_failure(&completed[0]["turn"]["error"], "another-model", None),
        MODEL_REASON
    );
}

#[test]
fn a_recorded_effort_refusal_names_the_model_effort_and_supported_levels() {
    let fixture = lines(EFFORT_REFUSED);
    let errors = method(&fixture, "error");
    assert_eq!(errors.len(), 1);
    assert_eq!(errors[0]["willRetry"], false);
    let completed = method(&fixture, "turn/completed");
    assert_eq!(completed[0]["turn"]["status"], "failed");
    let reason = codex_failure(&completed[0]["turn"]["error"], "gpt-5.3-codex", Some("max"));
    assert_eq!(reason, EFFORT_REASON);
    assert_credential_free(&reason);
    // The same refusal of the default effort names `medium`.
    let medium = json!({"message": "{\"error\": {\"message\": \"Unsupported value: 'medium' is not supported with the 'o1-pro' model. Supported values are: 'high'.\", \"type\": \"invalid_request_error\", \"param\": \"reasoning.effort\", \"code\": \"unsupported_value\"}}",
                        "codexErrorInfo": "other"});
    assert_eq!(
        codex_failure(&medium, "o1-pro", Some("medium")),
        "o1-pro does not support effort medium (supported: high); pass --effort"
    );
}

#[test]
fn a_recorded_completed_turn_reports_no_failure() {
    let fixture = lines(COMPLETED);
    assert!(method(&fixture, "error").is_empty());
    let completed = method(&fixture, "turn/completed");
    assert_eq!(completed[0]["turn"]["status"], "completed");
    assert!(completed[0]["turn"]["error"].is_null());
}

#[test]
fn transient_errors_are_not_refusals() {
    let disconnected = json!({"willRetry": true, "error": {
        "message": "Reconnecting... 1/5",
        "codexErrorInfo": {"responseStreamDisconnected": {"httpStatusCode": 503}},
        "additionalDetails": "unexpected status 503 Service Unavailable: upstream connect error, url: http://127.0.0.1:38081/v1/responses, request id: req_synthetic"}});
    assert_eq!(
        codex_retry_refusal(&disconnected, "gpt-6.1-sol", Some("medium")),
        None
    );
    let reason = codex_failure(&disconnected["error"], "gpt-6.1-sol", Some("medium"));
    assert_eq!(
        reason,
        "the provider refused the turn (HTTP 503): upstream connect error"
    );
    let limited = json!({"willRetry": true, "error": {"message": "Reconnecting... 2/5",
        "codexErrorInfo": {"responseTooManyFailedAttempts": {"httpStatusCode": 429}},
        "additionalDetails": "unexpected status 429 Too Many Requests: Rate limit reached"}});
    assert_eq!(codex_retry_refusal(&limited, "gpt-6.1-sol", None), None);
}

#[test]
fn a_missing_model_is_a_model_refusal() {
    let missing = json!({"message": "unexpected status 404 Not Found: {\"error\": {\"message\": \"The model `gpt-9` does not exist or you do not have access to it.\", \"type\": \"invalid_request_error\", \"param\": null, \"code\": \"model_not_found\"}}",
                         "codexErrorInfo": {"httpConnectionFailed": {"httpStatusCode": 404}}});
    assert_eq!(
        codex_failure(&missing, "gpt-9", Some("medium")),
        "this credential cannot use gpt-9 (the provider refused the model, HTTP 404); pass --model (and --effort)"
    );
}

#[test]
fn sanitizing_drops_identifiers_urls_and_secret_shapes() {
    // The key is assembled at run time so the source holds no key-shaped
    // literal for secret scanners; the sanitizer still sees the full shape.
    let key = ["sk", "proj", "SYNTHETIC0123456789abcdef"].join("-");
    let text = format!(
        "unexpected status 401 Unauthorized: Incorrect API key provided: {key} \
                for organization org-SYNTHETIC0000 user user-SYNTHETIC0000 via https://api.example.invalid/v1 \
                Authorization: Bearer synthetic.token.value eyJhbGciOiJIUzI1NiJ9.e30.SYNTHETIC \
                ghp_SYNTHETIC0000000000 opaque A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8 \
                model gpt-5.3-codex claude-3-5-sonnet-20241022, url: http://127.0.0.1:38081/v1/responses, cf-ray: abc-AMS, request id: req_1"
    );
    let clean = sanitize(&text);
    for leaked in [
        "sk-proj",
        "SYNTHETIC",
        "org-",
        "user-",
        "api.example",
        "synthetic.token",
        "eyJ",
        "ghp_",
        "A1b2C3",
        "127.0.0.1",
        "cf-ray",
        "req_",
    ] {
        assert!(!clean.contains(leaked), "{leaked} in {clean}");
    }
    // Model names, statuses and the provider's words remain.
    for kept in [
        "401 Unauthorized",
        "Incorrect API key provided",
        "gpt-5.3-codex",
        "claude-3-5-sonnet-20241022",
    ] {
        assert!(clean.contains(kept), "{kept} missing from {clean}");
    }
    assert!(!clean.contains('\n'));
    let long = sanitize(&"word ".repeat(1000));
    assert!(long.len() <= MAX_REASON_BYTES + '…'.len_utf8());
    assert!(long.ends_with('…'));
}

#[test]
fn claude_model_refusals_name_the_model() {
    assert_eq!(
        claude_failure(
            "success",
            r#"API Error: 404 {"type":"error","error":{"type":"not_found_error","message":"model: claude-opus-9"},"request_id":"req_SYNTHETIC"}"#,
            "claude-opus-5-5"
        ),
        "this credential cannot use claude-opus-9 (the provider refused the model, HTTP 404); pass --model"
    );
    assert_eq!(
        claude_failure(
            "success",
            "There's an issue with the selected model (claude-opus-9). It may not exist or you may not have access to it. Run /model to pick a different model.",
            "claude-opus-5-5"
        ),
        "this credential cannot use claude-opus-9 (the provider refused the model); pass --model"
    );
    let other = claude_failure(
        "success",
        r#"API Error: 400 {"type":"error","error":{"type":"invalid_request_error","message":"prompt is too long"},"request_id":"req_SYNTHETIC"}"#,
        "claude-opus-5-5",
    );
    assert_eq!(
        other,
        "Claude's turn failed: API Error: 400 prompt is too long"
    );
}

/// A peer that echoes what the driver sends it, one JSON line each.
fn echo_peer() -> Peer {
    let mut child = tokio::process::Command::new("cat")
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

/// What the driver sent the peer so far.
async fn sent(peer: &mut Peer) -> Vec<Value> {
    let mut lines = Vec::new();
    while let Ok(Some(NativeLine::Json(value))) =
        tokio::time::timeout(Duration::from_millis(300), peer.events.recv()).await
    {
        lines.push(value);
    }
    lines
}

struct Harness {
    _temporary: tempfile::TempDir,
    driver: Driver,
}

/// A Codex driver with private records in a temporary guest root, whose
/// native thread is the fixture's, and one running message.
fn running(fixture: &[Value], model: &str, effort: &str) -> (Harness, MessageRecord) {
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path().join("environment");
    let driver_id = uuid::Uuid::new_v4().to_string();
    let dir = root.join("agents").join(&driver_id);
    for path in [&root, &root.join("agents"), &dir, &dir.join("messages")] {
        crate::commands::host::private_directory(path).unwrap();
    }
    let environment = DriverEnvironment::Guest {
        id: uuid::Uuid::new_v4().to_string(),
        root,
    };
    let thread = fixture
        .iter()
        .find_map(|line| line.pointer("/params/threadId").and_then(Value::as_str))
        .unwrap()
        .to_owned();
    let created_at = now();
    let config = AgentConfig {
        version: 1,
        driver_id: driver_id.clone(),
        environment_id: environment.id().into(),
        agent: AgentKind::Codex,
        program: PathBuf::from("/usr/local/bin/codex"),
        program_fallback: None,
        model: model.into(),
        effort: Some(effort.into()),
        working_dir: "/workspace/project".into(),
        name: String::new(),
        parent: None,
        initial_message_id: None,
        created_at: created_at.clone(),
    };
    let binding = AgentBinding {
        driver_id: driver_id.clone(),
        session_id: "session".into(),
        bound_at: created_at.clone(),
    };
    let record = MessageRecord::new(
        &driver_id,
        "session",
        MessageAction::Message,
        "Reply with exactly CW2982_OK.".into(),
    );
    assert!(create_message(&dir, &record).unwrap());
    update_message(&dir, &record.id, |r| {
        r.transition(MessageState::Accepted);
        r.transition(MessageState::Running);
    })
    .unwrap();
    let driver = Driver {
        #[cfg(target_os = "linux")]
        platform: None,
        state: DriverState {
            version: 1,
            driver_id,
            agent: AgentKind::Codex,
            phase: DriverPhase::Busy,
            native_thread_id: Some(thread),
            native_thread_established: true,
            current_turn_id: None,
            active_message_id: Some(record.id.clone()),
            queued: 0,
            capabilities: AgentCapabilities {
                steer: true,
                interrupt: true,
                resume: false,
                note: String::new(),
            },
            policy: String::new(),
            last_error: None,
            started_at: created_at.clone(),
            updated_at: created_at.clone(),
        },
        active: Some(ActiveTurn {
            message_id: record.id.clone(),
            text: record.text.clone(),
            turn_id: None,
            texts: Vec::new(),
            steers: Vec::new(),
            interrupts: Vec::new(),
            usage: None,
            acknowledged: false,
            failure: None,
        }),
        config,
        environment,
        dir,
        binding,
        started_at: created_at,
        queue: VecDeque::new(),
        pending: HashMap::new(),
        control_pending: HashMap::new(),
        settled: HashSet::new(),
        stopping: false,
        noel: Default::default(),
        cw: None,
    };
    (
        Harness {
            _temporary: temporary,
            driver,
        },
        record,
    )
}

impl Harness {
    async fn replay(&mut self, peer: &mut Peer, fixture: &[Value]) {
        for line in fixture {
            self.driver.on_codex(peer, line.clone()).await.unwrap();
        }
    }

    fn load(&self, id: &str) -> MessageRecord {
        load_message(&self.driver.dir, id).unwrap()
    }

    /// The driver state `cw inbox` reads.
    fn saved_state(&self) -> DriverState {
        serde_json::from_slice(&std::fs::read(self.driver.dir.join("state.json")).unwrap()).unwrap()
    }
}

#[tokio::test]
async fn the_driver_ends_a_refused_model_turn_at_the_first_retry_and_records_why() {
    let fixture = lines(MODEL_REFUSED);
    let (mut harness, record) = running(&fixture, "gpt-6.1-sol", "medium");
    let mut peer = echo_peer();
    // Up to the first retry: the driver interrupts the turn at once.
    let first_retry = fixture
        .iter()
        .position(|line| line["method"] == "error")
        .unwrap();
    harness.replay(&mut peer, &fixture[..=first_retry]).await;
    let interrupts = sent(&mut peer).await;
    assert_eq!(interrupts.len(), 1, "{interrupts:?}");
    assert_eq!(interrupts[0]["method"], "turn/interrupt");
    let turn = harness
        .driver
        .active
        .as_ref()
        .unwrap()
        .turn_id
        .clone()
        .unwrap();
    assert_eq!(interrupts[0]["params"]["turnId"], turn);
    // Codex's later retries and its own failure change nothing and send
    // nothing more.
    harness.replay(&mut peer, &fixture[first_retry + 1..]).await;
    assert!(
        sent(&mut peer).await.is_empty(),
        "the driver retried or interrupted again"
    );
    let saved = harness.load(&record.id);
    assert_eq!(saved.state, MessageState::Error);
    assert_eq!(saved.error.as_deref(), Some(MODEL_REASON));
    assert_eq!(saved.turn_id.as_deref(), Some(turn.as_str()));
    let state = harness.saved_state();
    assert_eq!(state.phase, DriverPhase::Idle);
    assert_eq!(state.last_error.as_deref(), Some(MODEL_REASON));
    assert!(harness.driver.active.is_none());
}

#[tokio::test]
async fn a_refused_turn_codex_ends_as_interrupted_is_still_failed() {
    let fixture = lines(MODEL_REFUSED_INTERRUPTED);
    let (mut harness, record) = running(&fixture, "gpt-6.1-sol", "medium");
    let mut peer = echo_peer();
    harness.replay(&mut peer, &fixture).await;
    let interrupts = sent(&mut peer).await;
    assert_eq!(interrupts.len(), 1);
    let completed = method(&fixture, "turn/completed");
    assert_eq!(completed[0]["turn"]["status"], "interrupted");
    let saved = harness.load(&record.id);
    assert_eq!(saved.state, MessageState::Error);
    assert_eq!(saved.error.as_deref(), Some(MODEL_REASON));
    assert_eq!(
        harness.saved_state().last_error.as_deref(),
        Some(MODEL_REASON)
    );
}

#[tokio::test]
async fn the_driver_records_a_refused_effort_without_interrupting() {
    let fixture = lines(EFFORT_REFUSED);
    let (mut harness, record) = running(&fixture, "gpt-5.3-codex", "max");
    let mut peer = echo_peer();
    harness.replay(&mut peer, &fixture).await;
    assert!(sent(&mut peer).await.is_empty());
    let saved = harness.load(&record.id);
    assert_eq!(saved.state, MessageState::Error);
    assert_eq!(saved.error.as_deref(), Some(EFFORT_REASON));
    let state = harness.saved_state();
    assert_eq!(state.phase, DriverPhase::Idle);
    assert_eq!(state.last_error.as_deref(), Some(EFFORT_REASON));
}

/// A turn Codex calls completed, with no reply, after a final provider
/// error: as Codex records `task_complete` with no agent message.
#[tokio::test]
async fn a_completed_turn_with_no_reply_after_a_provider_error_is_failed() {
    let mut fixture = lines(EFFORT_REFUSED);
    let last = fixture.last_mut().unwrap();
    last["params"]["turn"]["status"] = json!("completed");
    last["params"]["turn"]["error"] = Value::Null;
    let (mut harness, record) = running(&fixture, "gpt-5.3-codex", "max");
    let mut peer = echo_peer();
    harness.replay(&mut peer, &fixture).await;
    let saved = harness.load(&record.id);
    assert_eq!(saved.state, MessageState::Error);
    assert_eq!(saved.error.as_deref(), Some(EFFORT_REASON));
}

#[tokio::test]
async fn a_completed_turn_records_the_reply_and_clears_the_last_error() {
    let fixture = lines(COMPLETED);
    let (mut harness, record) = running(&fixture, "gpt-6.1-sol", "medium");
    harness.driver.state.last_error = Some(MODEL_REASON.into());
    let mut peer = echo_peer();
    harness.replay(&mut peer, &fixture).await;
    assert!(sent(&mut peer).await.is_empty());
    let saved = harness.load(&record.id);
    assert_eq!(saved.state, MessageState::Completed);
    assert_eq!(saved.result.as_deref(), Some("CW2982_OK"));
    assert!(saved.error.is_none());
    let state = harness.saved_state();
    assert_eq!(state.phase, DriverPhase::Idle);
    assert_eq!(state.last_error, None);
}

fn session_view(name: &str) -> crate::commands::sessions::EnvironmentSessionView {
    crate::commands::sessions::EnvironmentSessionView {
        session_id: "session-11111111-1111-4111-8111-111111111111".into(),
        name: name.into(),
        parent_session_id: String::new(),
        cleanup_unknown: false,
        started_at: String::new(),
        launch_generation: 1,
        state: "Running".into(),
        command: Vec::new(),
        working_dir: "/workspace".into(),
        pty: false,
        exit_code: None,
        output_end_offset: 0,
        output_start_offset: 0,
        status_message: String::new(),
    }
}

#[test]
fn info_names_each_failed_conversation_with_its_repair_and_inbox() {
    use crate::commands::sessions::agents::{
        ManagedAttentionReport, attention_entry, managed_attention_json, managed_attention_rows,
    };
    let view = session_view("lead");
    // A well conversation needs no row.
    let well = json!({"agent": "codex", "phase": "idle", "last_error": null});
    assert_eq!(attention_entry("app", &view, &well), None);
    let failed = json!({"agent": "codex", "phase": "idle", "last_error": MODEL_REASON});
    let entry = attention_entry("app", &view, &failed).unwrap();
    assert_eq!(entry.state, "turn_failed");
    let report = ManagedAttentionReport::Sessions(vec![entry]);
    assert_eq!(
        managed_attention_rows(&report),
        [format!(
            "lead (codex) last turn failed: {MODEL_REASON}. See `cw inbox app --session lead`"
        )]
    );
    let entries = managed_attention_json(&report).unwrap();
    assert_eq!(entries[0]["session"], "lead");
    assert_eq!(entries[0]["reason"], MODEL_REASON);
    assert_eq!(entries[0]["inbox_command"], "cw inbox app --session lead");
    // An earlier driver's raw provider text is shown only as sanitized.
    let raw = json!({"agent": "codex", "phase": "failed",
        "last_error": "unexpected status 403 Forbidden: Project `proj_SYNTHETIC0000` does not have access to model `gpt-6.1-sol`, url: http://127.0.0.1:38081/v1/responses"});
    let entry = attention_entry("app", &session_view(""), &raw).unwrap();
    assert_eq!(entry.state, "driver_failed");
    assert_credential_free(&entry.reason);
    assert!(
        entry
            .inbox_command
            .ends_with("--session session-11111111-1111-4111-8111-111111111111")
    );
    // No conversation needing attention adds nothing; an unreadable one says so.
    let none = ManagedAttentionReport::Sessions(Vec::new());
    assert!(managed_attention_rows(&none).is_empty());
    assert_eq!(managed_attention_json(&none), None);
    let unavailable =
        ManagedAttentionReport::Unavailable("listing its sessions took longer than 3 s".into());
    assert_eq!(
        managed_attention_rows(&unavailable),
        ["agents: unavailable (listing its sessions took longer than 3 s)"]
    );
    assert_eq!(managed_attention_json(&unavailable), None);
}
