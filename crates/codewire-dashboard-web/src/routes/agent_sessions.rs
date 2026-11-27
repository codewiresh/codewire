//! Browser BFF and push-based SSE stream for managed Sandbox agent sessions.
//!
//! Security boundary:
//! - Every route requires an authenticated session with two-factor enforced,
//!   organization membership, and `organization.agent_chat == true` (returns
//!   403 `agent-chat-disabled` when off).
//! - Mutations require exact same-origin `Origin`, valid CSRF token, matching
//!   `account_id`, `#[serde(deny_unknown_fields)]`, closed enums, and bounded
//!   payloads; provider credentials never cross this boundary.
//! - Live streaming attaches to the managed driver's durable session via
//!   `EnvironmentSessionService::AttachSession` (zero polling) and forwards
//!   only validated `\x1eCW_AGENT_V1 {...}` events as SSE frames.

use std::{convert::Infallible, time::Duration};

use axum::{
    Json,
    body::{Body, Bytes},
    extract::{Path, Query, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::Response,
};
use codewire_proto::codewire::v1::{
    AttachSessionOpen, AttachSessionRequest, AttachSessionResponse, EnvironmentAgentAction,
    EnvironmentAgentControl, EnvironmentAgentKind, EnvironmentAgentLaunch, EnvironmentAgentPhase,
    EnvironmentAgentRecordKind, EnvironmentAgentScope, EnvironmentAgentServiceClient,
    EnvironmentAgentSupport, EnvironmentSession, EnvironmentSessionOutputStream,
    EnvironmentSessionServiceClient, EnvironmentSessionState, GetEnvironmentAgentInfoRequest,
    ListEnvironmentAgentsRequest, MutateEnvironmentAgentRequest, ReadEnvironmentAgentRequest,
    attach_session_request, attach_session_response, mutate_environment_agent_request,
};
use connectrpc::{ConnectError, ErrorCode, client::ClientConfig};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tokio::sync::mpsc;
use tokio_stream::{StreamExt as _, wrappers::ReceiverStream};

use crate::{
    auth::{authenticated_identity, enforce_two_factor},
    error::{WebError, codewire_reason},
    routes::terminal::canonical_environment_id,
    routes::terminal_sessions::{failure, json as json_response, valid_action},
    security::canonical_cookie,
    state::AppState,
    transport::BrowserTransport,
};

const STREAM_EVENT_PREFIX: &str = "\x1eCW_AGENT_V1 ";
const HEARTBEAT_FRAME: &str = ": heartbeat\n\n";
const STREAM_LIFETIME: Duration = Duration::from_secs(30 * 60);
const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(15);
const MAX_LINE_BUFFER_BYTES: usize = 64 * 1024;
const MAX_EVENT_JSON_BYTES: usize = 32 * 1024;
const MAX_PROMPT_BYTES: usize = 32 * 1024;
const MAX_WORKING_DIR_BYTES: usize = 512;
const MAX_MODEL_BYTES: usize = 128;
const MAX_READ_MESSAGES: usize = 20;

struct AgentContext {
    account_id: String,
    org_id: String,
    cookie: HeaderValue,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SupportedAgentView {
    agent: &'static str,
    version: String,
    steer: bool,
    interrupt: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct AgentSessionSummary {
    session_id: String,
    driver_id: String,
    launch_generation: u64,
    name: String,
    state: &'static str,
    working_dir: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct AgentInventoryResponse {
    account_id: String,
    supported_agents: Vec<SupportedAgentView>,
    sessions: Vec<AgentSessionSummary>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct AgentOperationView {
    request_id: String,
    session_id: String,
    driver_id: String,
    launch_generation: u64,
    message_id: String,
    phase: &'static str,
    state: &'static str,
    reason: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct AgentThreadResponse {
    session_id: String,
    driver_id: String,
    launch_generation: u64,
    current: Value,
    messages: Vec<Value>,
}

// No Debug: CSRF and user prompts are private authority/content.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct LaunchAgentBody {
    #[serde(rename = "_csrf")]
    csrf: String,
    account_id: String,
    request_id: String,
    agent: String,
    model: String,
    #[serde(default)]
    effort: Option<String>,
    working_dir: String,
    prompt: String,
    #[serde(default)]
    name: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ControlAgentBody {
    #[serde(rename = "_csrf")]
    csrf: String,
    account_id: String,
    request_id: String,
    action: String,
    session_id: String,
    driver_id: String,
    launch_generation: u64,
    #[serde(default)]
    text: String,
}

#[derive(Deserialize)]
pub(super) struct ReadAgentQuery {
    driver_id: String,
    launch_generation: u64,
}

#[derive(Default, Deserialize)]
pub(super) struct EventsQuery {
    #[serde(default)]
    offset: Option<u64>,
}

fn web_failure(error: WebError) -> Response {
    match error {
        WebError::Unauthorized => failure(StatusCode::UNAUTHORIZED, "sign-in-required"),
        WebError::TwoFactorRequired => failure(StatusCode::FORBIDDEN, "two-factor-required"),
        WebError::NotFound => failure(StatusCode::NOT_FOUND, "not-found"),
        WebError::Connect(error) => connect_failure(error, false),
        _ => failure(StatusCode::SERVICE_UNAVAILABLE, "agents-unavailable"),
    }
}

fn connect_failure(error: ConnectError, mutation: bool) -> Response {
    match error.code {
        ErrorCode::Unauthenticated => failure(StatusCode::UNAUTHORIZED, "sign-in-required"),
        ErrorCode::PermissionDenied => failure(StatusCode::FORBIDDEN, "not-authorized"),
        ErrorCode::NotFound => failure(StatusCode::NOT_FOUND, "not-found"),
        ErrorCode::InvalidArgument => failure(StatusCode::BAD_REQUEST, "invalid-request"),
        ErrorCode::FailedPrecondition
            if codewire_reason(&error).ok().flatten().as_deref()
                == Some("ORGANIZATION_DELETING") =>
        {
            failure(StatusCode::CONFLICT, "organization-deleting")
        }
        ErrorCode::FailedPrecondition => failure(StatusCode::CONFLICT, "agent-unavailable"),
        ErrorCode::ResourceExhausted if mutation => failure(StatusCode::CONFLICT, "session-limit"),
        _ if mutation => failure(StatusCode::CONFLICT, "agent-outcome-unknown"),
        _ => failure(StatusCode::SERVICE_UNAVAILABLE, "agents-unavailable"),
    }
}

fn valid_account_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

fn valid_session_id(value: &str) -> bool {
    value
        .strip_prefix("session-")
        .is_some_and(canonical_environment_id)
}

fn valid_working_dir(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_WORKING_DIR_BYTES
        && value.starts_with('/')
        && !value.chars().any(char::is_control)
}

fn valid_model_token(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_MODEL_BYTES
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._:/-".contains(&b))
}

fn normalize_effort(effort: Option<&str>) -> Result<Option<String>, ()> {
    let Some(raw) = effort.map(str::trim).filter(|s| !s.is_empty()) else {
        return Ok(None);
    };
    let lower = raw.to_ascii_lowercase();
    match lower.as_str() {
        "default" => Ok(None),
        "low" | "medium" | "high" | "xhigh" | "max" => Ok(Some(lower)),
        _ => Err(()),
    }
}

fn parse_agent_kind(value: &str) -> Option<EnvironmentAgentKind> {
    match value {
        "codex" => Some(EnvironmentAgentKind::Codex),
        "claude" => Some(EnvironmentAgentKind::Claude),
        "agy" => Some(EnvironmentAgentKind::Agy),
        _ => None,
    }
}

fn agent_kind_name(kind: i32) -> Option<&'static str> {
    match kind {
        v if v == EnvironmentAgentKind::Codex as i32 => Some("codex"),
        v if v == EnvironmentAgentKind::Claude as i32 => Some("claude"),
        v if v == EnvironmentAgentKind::Agy as i32 => Some("agy"),
        _ => None,
    }
}

fn parse_agent_action(value: &str) -> Option<EnvironmentAgentAction> {
    match value {
        "message" => Some(EnvironmentAgentAction::Message),
        "steer" => Some(EnvironmentAgentAction::Steer),
        "interrupt" => Some(EnvironmentAgentAction::Interrupt),
        "stop" => Some(EnvironmentAgentAction::Stop),
        "resume" => Some(EnvironmentAgentAction::Resume),
        _ => None,
    }
}

fn phase_name(phase: i32) -> &'static str {
    match phase {
        v if v == EnvironmentAgentPhase::Admitted as i32 => "admitted",
        v if v == EnvironmentAgentPhase::Issued as i32 => "issued",
        v if v == EnvironmentAgentPhase::Completed as i32 => "completed",
        v if v == EnvironmentAgentPhase::Rejected as i32 => "rejected",
        v if v == EnvironmentAgentPhase::Unknown as i32 => "unknown",
        _ => "unknown",
    }
}

fn session_state_name(state: i32) -> &'static str {
    match state {
        v if v == EnvironmentSessionState::Starting as i32 => "starting",
        v if v == EnvironmentSessionState::Running as i32 => "running",
        v if v == EnvironmentSessionState::Stopping as i32 => "stopping",
        v if v == EnvironmentSessionState::Stopped as i32 => "stopped",
        v if v == EnvironmentSessionState::Exited as i32 => "exited",
        v if v == EnvironmentSessionState::Failed as i32 => "failed",
        v if v == EnvironmentSessionState::Interrupted as i32 => "interrupted",
        _ => "unknown",
    }
}

#[expect(clippy::result_large_err, reason = "the error is the HTTP response")]
async fn context(
    state: &AppState,
    headers: &HeaderMap,
    slug: &str,
    environment_id: &str,
) -> Result<AgentContext, Response> {
    if !codewire_server_core::organization_slug::valid_organization_slug(slug)
        || !canonical_environment_id(environment_id)
    {
        return Err(failure(StatusCode::NOT_FOUND, "not-found"));
    }
    let identity = authenticated_identity(state, headers)
        .await
        .map_err(web_failure)?;
    enforce_two_factor(&identity).map_err(web_failure)?;
    if !valid_account_id(&identity.id) {
        return Err(failure(
            StatusCode::SERVICE_UNAVAILABLE,
            "agents-unavailable",
        ));
    }
    let cookie = canonical_cookie(headers)
        .map_err(|()| failure(StatusCode::UNAUTHORIZED, "sign-in-required"))?;
    let dashboard = super::dashboard::dashboard_shell_view_from_identity(
        state,
        headers,
        &identity,
        cookie.clone(),
    )
    .await
    .map_err(web_failure)?;
    let organization = dashboard
        .organizations
        .iter()
        .find(|organization| organization.slug == slug)
        .ok_or_else(|| failure(StatusCode::NOT_FOUND, "not-found"))?;
    if !organization.agent_chat {
        return Err(failure(StatusCode::FORBIDDEN, "agent-chat-disabled"));
    }
    Ok(AgentContext {
        account_id: identity.id,
        org_id: organization.id.clone(),
        cookie,
    })
}

fn agent_client(
    state: &AppState,
    cookie: HeaderValue,
) -> EnvironmentAgentServiceClient<BrowserTransport> {
    EnvironmentAgentServiceClient::new(
        BrowserTransport {
            http: state.session_http.clone(),
            cookie: Some(cookie),
            origin: None,
        },
        ClientConfig::new(state.api_origin.clone())
            .with_default_timeout(Duration::from_secs(80))
            .with_default_max_message_size(6 * 1024 * 1024),
    )
}

fn bidi_session_client(
    state: &AppState,
    cookie: HeaderValue,
) -> EnvironmentSessionServiceClient<BrowserTransport> {
    EnvironmentSessionServiceClient::new(
        BrowserTransport {
            http: state.bidi_http.clone(),
            cookie: Some(cookie),
            origin: None,
        },
        ClientConfig::new(state.api_origin.clone()).with_default_max_message_size(1024 * 1024),
    )
}

fn session_summary(session: EnvironmentSession) -> Option<AgentSessionSummary> {
    let driver_id = session.session_id.strip_prefix("session-")?.to_owned();
    if !canonical_environment_id(&driver_id) {
        return None;
    }
    Some(AgentSessionSummary {
        session_id: session.session_id,
        driver_id,
        launch_generation: session.launch_generation,
        name: session.name,
        state: session_state_name(session.state.to_i32()),
        working_dir: session.working_dir,
    })
}

fn supported_view(support: &EnvironmentAgentSupport) -> Option<SupportedAgentView> {
    if !support.proxy_only_qualified {
        return None;
    }
    Some(SupportedAgentView {
        agent: agent_kind_name(support.agent.to_i32())?,
        version: support.provider_version.clone(),
        steer: support.steer,
        interrupt: support.interrupt,
    })
}

pub(super) async fn list(
    State(state): State<AppState>,
    Path((slug, environment_id)): Path<(String, String)>,
    headers: HeaderMap,
) -> Response {
    let ctx = match context(&state, &headers, &slug, &environment_id).await {
        Ok(value) => value,
        Err(response) => return response,
    };
    let rpc = agent_client(&state, ctx.cookie);
    let info = match rpc
        .get_environment_agent_info(GetEnvironmentAgentInfoRequest {
            org_id: ctx.org_id.clone(),
            environment_id: environment_id.clone(),
            ..Default::default()
        })
        .await
    {
        Ok(response) => response.into_owned(),
        Err(error) => return connect_failure(error, false),
    };
    let Some(scope) = info.scope.into_option() else {
        return failure(StatusCode::BAD_GATEWAY, "agents-unavailable");
    };
    let supported_agents = info.agents.iter().filter_map(supported_view).collect();
    let listed = match rpc
        .list_environment_agents(ListEnvironmentAgentsRequest {
            org_id: ctx.org_id,
            environment_id,
            expected_scope: Some(scope).into(),
            ..Default::default()
        })
        .await
    {
        Ok(response) => response.into_owned(),
        Err(error) => return connect_failure(error, false),
    };
    let sessions = listed
        .sessions
        .into_iter()
        .filter_map(session_summary)
        .collect();
    json_response(
        StatusCode::OK,
        AgentInventoryResponse {
            account_id: ctx.account_id,
            supported_agents,
            sessions,
        },
    )
}

pub(super) async fn launch(
    State(state): State<AppState>,
    Path((slug, environment_id)): Path<(String, String)>,
    headers: HeaderMap,
    Json(body): Json<LaunchAgentBody>,
) -> Response {
    if !valid_action(&state.public_origin, &headers, &body.csrf) {
        return failure(StatusCode::FORBIDDEN, "request-rejected");
    }
    let Some(agent) = parse_agent_kind(&body.agent) else {
        return failure(StatusCode::BAD_REQUEST, "unsupported-agent");
    };
    if !canonical_environment_id(&body.request_id)
        || !valid_model_token(&body.model)
        || !valid_working_dir(&body.working_dir)
        || body.prompt.trim().is_empty()
        || body.prompt.len() > MAX_PROMPT_BYTES
        || body.prompt.contains('\0')
    {
        return failure(StatusCode::BAD_REQUEST, "invalid-request");
    }
    let Ok(effort) = normalize_effort(body.effort.as_deref()) else {
        return failure(StatusCode::BAD_REQUEST, "invalid-request");
    };
    let ctx = match context(&state, &headers, &slug, &environment_id).await {
        Ok(value) => value,
        Err(response) => return response,
    };
    if ctx.account_id != body.account_id {
        return failure(StatusCode::CONFLICT, "account-changed");
    }
    let rpc = agent_client(&state, ctx.cookie);
    let info = match rpc
        .get_environment_agent_info(GetEnvironmentAgentInfoRequest {
            org_id: ctx.org_id.clone(),
            environment_id: environment_id.clone(),
            ..Default::default()
        })
        .await
    {
        Ok(response) => response.into_owned(),
        Err(error) => return connect_failure(error, false),
    };
    let Some(scope) = info.scope.into_option() else {
        return failure(StatusCode::BAD_GATEWAY, "agents-unavailable");
    };
    let Some(support) = info
        .agents
        .iter()
        .find(|item| item.agent.to_i32() == agent as i32 && item.proxy_only_qualified)
    else {
        return failure(StatusCode::CONFLICT, "agent-not-configured");
    };
    let name = body
        .name
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty() && s.len() <= 64 && !s.chars().any(char::is_control))
        .unwrap_or_default()
        .to_owned();
    let request = MutateEnvironmentAgentRequest {
        org_id: ctx.org_id,
        environment_id,
        request_id: body.request_id,
        expected_scope: Some(scope).into(),
        operation: Some(mutate_environment_agent_request::Operation::Launch(
            Box::new(EnvironmentAgentLaunch {
                agent: agent.into(),
                model: body.model,
                effort,
                working_dir: body.working_dir,
                name,
                prompt: Some(body.prompt),
                expected_provider_sha256: support.provider_sha256.clone(),
                expected_provider_size: support.provider_size,
                expected_provider_version: support.provider_version.clone(),
                ..Default::default()
            }),
        )),
        ..Default::default()
    };
    match rpc.mutate_environment_agent(request).await {
        Ok(response) => {
            let Some(op) = response.into_owned().operation.into_option() else {
                return failure(StatusCode::CONFLICT, "agent-outcome-unknown");
            };
            json_response(
                StatusCode::OK,
                AgentOperationView {
                    request_id: op.request_id,
                    session_id: op.session_id,
                    driver_id: op.driver_id,
                    launch_generation: op.launch_generation,
                    message_id: op.message_id,
                    phase: phase_name(op.phase.to_i32()),
                    state: session_state_name(op.lifecycle.to_i32()),
                    reason: op.reason_code,
                },
            )
        }
        Err(error) => connect_failure(error, true),
    }
}

pub(super) async fn control(
    State(state): State<AppState>,
    Path((slug, environment_id)): Path<(String, String)>,
    headers: HeaderMap,
    Json(body): Json<ControlAgentBody>,
) -> Response {
    if !valid_action(&state.public_origin, &headers, &body.csrf) {
        return failure(StatusCode::FORBIDDEN, "request-rejected");
    }
    let Some(action) = parse_agent_action(&body.action) else {
        return failure(StatusCode::BAD_REQUEST, "invalid-request");
    };
    let needs_text = matches!(
        action,
        EnvironmentAgentAction::Message | EnvironmentAgentAction::Steer
    );
    if !canonical_environment_id(&body.request_id)
        || !valid_session_id(&body.session_id)
        || !canonical_environment_id(&body.driver_id)
        || body.launch_generation == 0
        || body.text.len() > MAX_PROMPT_BYTES
        || body.text.contains('\0')
        || (needs_text && body.text.trim().is_empty())
    {
        return failure(StatusCode::BAD_REQUEST, "invalid-request");
    }
    let ctx = match context(&state, &headers, &slug, &environment_id).await {
        Ok(value) => value,
        Err(response) => return response,
    };
    if ctx.account_id != body.account_id {
        return failure(StatusCode::CONFLICT, "account-changed");
    }
    let rpc = agent_client(&state, ctx.cookie);
    let info = match rpc
        .get_environment_agent_info(GetEnvironmentAgentInfoRequest {
            org_id: ctx.org_id.clone(),
            environment_id: environment_id.clone(),
            ..Default::default()
        })
        .await
    {
        Ok(response) => response.into_owned(),
        Err(error) => return connect_failure(error, false),
    };
    let Some(scope) = info.scope.into_option() else {
        return failure(StatusCode::BAD_GATEWAY, "agents-unavailable");
    };
    let request = MutateEnvironmentAgentRequest {
        org_id: ctx.org_id,
        environment_id,
        request_id: body.request_id,
        expected_scope: Some(scope).into(),
        operation: Some(mutate_environment_agent_request::Operation::Control(
            Box::new(EnvironmentAgentControl {
                action: action.into(),
                session_id: body.session_id,
                driver_id: body.driver_id,
                expected_launch_generation: body.launch_generation,
                text: body.text,
                ..Default::default()
            }),
        )),
        ..Default::default()
    };
    match rpc.mutate_environment_agent(request).await {
        Ok(response) => {
            let Some(op) = response.into_owned().operation.into_option() else {
                return failure(StatusCode::CONFLICT, "agent-outcome-unknown");
            };
            json_response(
                StatusCode::OK,
                AgentOperationView {
                    request_id: op.request_id,
                    session_id: op.session_id,
                    driver_id: op.driver_id,
                    launch_generation: op.launch_generation,
                    message_id: op.message_id,
                    phase: phase_name(op.phase.to_i32()),
                    state: session_state_name(op.lifecycle.to_i32()),
                    reason: op.reason_code,
                },
            )
        }
        Err(error) => connect_failure(error, true),
    }
}

pub(super) async fn read(
    State(state): State<AppState>,
    Path((slug, environment_id, session_id)): Path<(String, String, String)>,
    Query(query): Query<ReadAgentQuery>,
    headers: HeaderMap,
) -> Response {
    if !valid_session_id(&session_id)
        || !canonical_environment_id(&query.driver_id)
        || query.launch_generation == 0
    {
        return failure(StatusCode::BAD_REQUEST, "invalid-request");
    }
    let ctx = match context(&state, &headers, &slug, &environment_id).await {
        Ok(value) => value,
        Err(response) => return response,
    };
    let rpc = agent_client(&state, ctx.cookie);
    let info = match rpc
        .get_environment_agent_info(GetEnvironmentAgentInfoRequest {
            org_id: ctx.org_id.clone(),
            environment_id: environment_id.clone(),
            ..Default::default()
        })
        .await
    {
        Ok(response) => response.into_owned(),
        Err(error) => return connect_failure(error, false),
    };
    let Some(scope) = info.scope.into_option() else {
        return failure(StatusCode::BAD_GATEWAY, "agents-unavailable");
    };
    let current_response = match rpc
        .read_environment_agent(ReadEnvironmentAgentRequest {
            org_id: ctx.org_id.clone(),
            environment_id: environment_id.clone(),
            expected_scope: Some(scope.clone()).into(),
            session_id: session_id.clone(),
            driver_id: query.driver_id.clone(),
            expected_launch_generation: query.launch_generation,
            kind: EnvironmentAgentRecordKind::Current.into(),
            limit: MAX_READ_MESSAGES as u32,
            ..Default::default()
        })
        .await
    {
        Ok(response) => response.into_owned(),
        Err(error) => return connect_failure(error, false),
    };
    let current: Value = match serde_json::from_slice(&current_response.record_json) {
        Ok(value) => value,
        Err(_) => return failure(StatusCode::BAD_GATEWAY, "agents-unavailable"),
    };
    let mut messages = Vec::new();
    if let Some(items) = current.get("messages").and_then(Value::as_array) {
        for summary in items.iter().take(MAX_READ_MESSAGES) {
            let Some(message_id) = summary.get("id").and_then(Value::as_str) else {
                continue;
            };
            if !canonical_environment_id(message_id) {
                continue;
            }
            if let Ok(record) = read_one_message(
                &rpc,
                &ctx.org_id,
                &environment_id,
                &scope,
                &session_id,
                &query.driver_id,
                query.launch_generation,
                message_id,
            )
            .await
            {
                messages.push(record);
            }
        }
    }
    json_response(
        StatusCode::OK,
        AgentThreadResponse {
            session_id,
            driver_id: query.driver_id,
            launch_generation: query.launch_generation,
            current,
            messages,
        },
    )
}

#[expect(clippy::too_many_arguments, reason = "explicit RPC coordinates")]
async fn read_one_message(
    rpc: &EnvironmentAgentServiceClient<BrowserTransport>,
    org_id: &str,
    environment_id: &str,
    scope: &EnvironmentAgentScope,
    session_id: &str,
    driver_id: &str,
    launch_generation: u64,
    message_id: &str,
) -> Result<Value, ()> {
    let response = rpc
        .read_environment_agent(ReadEnvironmentAgentRequest {
            org_id: org_id.to_owned(),
            environment_id: environment_id.to_owned(),
            expected_scope: Some(scope.clone()).into(),
            session_id: session_id.to_owned(),
            driver_id: driver_id.to_owned(),
            expected_launch_generation: launch_generation,
            kind: EnvironmentAgentRecordKind::Message.into(),
            message_id: message_id.to_owned(),
            ..Default::default()
        })
        .await
        .map_err(|_| ())?;
    serde_json::from_slice(&response.into_owned().record_json).map_err(|_| ())
}

/// Line-oriented extractor for `\x1eCW_AGENT_V1 {...}\n` events from raw
/// session stdout chunks. Non-prefixed lines and invalid/oversized payloads
/// are discarded safely.
struct EventLineParser {
    buffer: Vec<u8>,
    dropping_oversized_line: bool,
}

impl EventLineParser {
    fn new() -> Self {
        Self {
            buffer: Vec::new(),
            dropping_oversized_line: false,
        }
    }

    fn push(&mut self, chunk_start: u64, bytes: &[u8]) -> Vec<(&'static str, String, u64)> {
        let mut events = Vec::new();
        for (index, &byte) in bytes.iter().enumerate() {
            if byte == b'\n' {
                if !self.dropping_oversized_line
                    && let Some((event_type, canonical)) = parse_event_line(&self.buffer)
                {
                    let end_offset = chunk_start.saturating_add(index as u64).saturating_add(1);
                    events.push((event_type, canonical, end_offset));
                }
                self.buffer.clear();
                self.dropping_oversized_line = false;
                continue;
            }
            if self.dropping_oversized_line {
                continue;
            }
            if self.buffer.len() >= MAX_LINE_BUFFER_BYTES {
                self.buffer.clear();
                self.dropping_oversized_line = true;
                continue;
            }
            self.buffer.push(byte);
        }
        events
    }
}

fn parse_event_line(raw: &[u8]) -> Option<(&'static str, String)> {
    let line = std::str::from_utf8(raw).ok()?.trim_end_matches('\r');
    let payload = line.strip_prefix(STREAM_EVENT_PREFIX)?;
    if payload.len() > MAX_EVENT_JSON_BYTES {
        return None;
    }
    let parsed: Value = serde_json::from_str(payload).ok()?;
    if parsed.get("v").and_then(Value::as_u64) != Some(1) {
        return None;
    }
    let event_type = match parsed.get("t").and_then(Value::as_str)? {
        "turn_start" => "turn_start",
        "delta" => "delta",
        "tool_start" => "tool_start",
        "tool_end" => "tool_end",
        "turn_end" => "turn_end",
        _ => return None,
    };
    let canonical = serde_json::to_string(&parsed).ok()?;
    Some((event_type, canonical))
}

fn sse_frame(id: Option<u64>, event: &str, data: &str) -> Bytes {
    match id {
        Some(offset) => Bytes::from(format!("id: {offset}\nevent: {event}\ndata: {data}\n\n")),
        None => Bytes::from(format!("event: {event}\ndata: {data}\n\n")),
    }
}

fn sse_response(body: Body) -> Response {
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "text/event-stream; charset=utf-8")
        .header(header::CACHE_CONTROL, "no-store")
        .header(header::VARY, "Cookie")
        .header(header::X_CONTENT_TYPE_OPTIONS, "nosniff")
        .header("x-accel-buffering", "no")
        .body(body)
        .expect("static agent SSE headers")
}

fn resume_offset(headers: &HeaderMap, query: &EventsQuery) -> u64 {
    headers
        .get("last-event-id")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.trim().parse::<u64>().ok())
        .or(query.offset)
        .unwrap_or(0)
}

pub(super) async fn events(
    State(state): State<AppState>,
    Path((slug, environment_id, session_id)): Path<(String, String, String)>,
    Query(query): Query<EventsQuery>,
    headers: HeaderMap,
) -> Response {
    if !valid_session_id(&session_id) {
        return failure(StatusCode::BAD_REQUEST, "invalid-request");
    }
    let ctx = match context(&state, &headers, &slug, &environment_id).await {
        Ok(value) => value,
        Err(response) => return response,
    };
    let offset = resume_offset(&headers, &query);
    let rpc = bidi_session_client(&state, ctx.cookie);
    let mut stream = match rpc.attach_session().await {
        Ok(stream) => stream,
        Err(error) => return connect_failure(error, false),
    };
    let open = AttachSessionOpen {
        org_id: ctx.org_id,
        environment_id,
        session_id,
        output_offset: offset,
        ..Default::default()
    };
    if let Err(error) = stream
        .send(AttachSessionRequest {
            input: Some(attach_session_request::Input::Open(Box::new(open))),
            ..Default::default()
        })
        .await
    {
        return connect_failure(error, false);
    }
    let first = match stream.message::<AttachSessionResponse>().await {
        Ok(Some(message)) => message.to_owned_message(),
        Ok(None) => return failure(StatusCode::SERVICE_UNAVAILABLE, "agents-unavailable"),
        Err(error) => return connect_failure(error, false),
    };
    let (frames, receiver) = mpsc::channel::<Bytes>(64);
    tokio::spawn(async move {
        let _ = tokio::time::timeout(STREAM_LIFETIME, async move {
            let mut parser = EventLineParser::new();
            if !forward_attach_response(&first, &mut parser, &frames).await {
                return;
            }
            let mut heartbeat = tokio::time::interval(HEARTBEAT_INTERVAL);
            heartbeat.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            heartbeat.tick().await;
            loop {
                tokio::select! {
                    () = frames.closed() => return,
                    _ = heartbeat.tick() => {
                        if frames.send(Bytes::from_static(HEARTBEAT_FRAME.as_bytes())).await.is_err() {
                            return;
                        }
                    }
                    next = stream.message::<AttachSessionResponse>() => {
                        match next {
                            Ok(Some(msg)) => {
                                let owned = msg.to_owned_message();
                                if !forward_attach_response(&owned, &mut parser, &frames).await {
                                    return;
                                }
                            }
                            Ok(None) | Err(_) => return,
                        }
                    }
                }
            }
        })
        .await;
    });
    sse_response(Body::from_stream(
        ReceiverStream::new(receiver).map(Ok::<Bytes, Infallible>),
    ))
}

async fn forward_attach_response(
    response: &AttachSessionResponse,
    parser: &mut EventLineParser,
    frames: &mpsc::Sender<Bytes>,
) -> bool {
    match response.event.as_ref() {
        Some(attach_session_response::Event::Output(chunk)) => {
            if chunk.stream.to_i32() != EnvironmentSessionOutputStream::Stdout as i32 {
                return true;
            }
            let chunk_start = chunk.next_offset.saturating_sub(chunk.data.len() as u64);
            for (event_type, data, end_offset) in parser.push(chunk_start, &chunk.data) {
                let frame = sse_frame(Some(end_offset), event_type, &data);
                if frames.send(frame).await.is_err() {
                    return false;
                }
            }
            true
        }
        Some(attach_session_response::Event::Status(status)) => {
            let state = session_state_name(status.session.state.to_i32());
            let data = json!({ "state": state }).to_string();
            frames.send(sse_frame(None, "status", &data)).await.is_ok()
        }
        Some(attach_session_response::Event::HistoryGap(gap)) => {
            let data = json!({ "nextOffset": gap.retained_start_offset }).to_string();
            frames
                .send(sse_frame(Some(gap.retained_start_offset), "resync", &data))
                .await
                .is_ok()
        }
        None => true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn event_line_parser_extracts_split_v1_events_and_ignores_other_lines() {
        let mut parser = EventLineParser::new();
        let log_line = b"plain log line\n";
        assert!(parser.push(0, log_line).is_empty());
        let part1 = format!("{STREAM_EVENT_PREFIX}{{\"v\":1,\"t\":\"delta\",");
        let part2 = "\"msg\":\"m1\",\"text\":\"hi\"}\n";
        let offset1 = log_line.len() as u64;
        assert!(parser.push(offset1, part1.as_bytes()).is_empty());
        let offset2 = offset1 + part1.len() as u64;
        let events = parser.push(offset2, part2.as_bytes());
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].0, "delta");
        assert_eq!(events[0].2, offset2 + part2.len() as u64);
        let value: Value = serde_json::from_str(&events[0].1).unwrap();
        assert_eq!(value["text"], "hi");
    }

    #[test]
    fn event_line_parser_stamps_exact_post_newline_offset_before_trailing_partial_line() {
        let event_a = format!(
            "{STREAM_EVENT_PREFIX}{{\"v\":1,\"t\":\"delta\",\"msg\":\"m1\",\"text\":\"A\"}}\n"
        );
        let event_b = format!(
            "{STREAM_EVENT_PREFIX}{{\"v\":1,\"t\":\"delta\",\"msg\":\"m1\",\"text\":\"B\"}}\n"
        );
        let split_at = event_b.len() / 2;
        let mut full_stream = Vec::new();
        full_stream.extend_from_slice(event_a.as_bytes());
        full_stream.extend_from_slice(event_b.as_bytes());

        // Chunk 1 carries all of event A plus the first half of event B.
        let chunk1_end = event_a.len() + split_at;
        let mut parser = EventLineParser::new();
        let first_events = parser.push(0, &full_stream[..chunk1_end]);
        assert_eq!(first_events.len(), 1);
        assert_eq!(first_events[0].0, "delta");
        let resume_id = first_events[0].2;
        assert_eq!(
            resume_id,
            event_a.len() as u64,
            "SSE id must point right after event A's newline, not chunk.next_offset"
        );
        assert!(resume_id < chunk1_end as u64);

        // Reconnecting with Last-Event-ID = resume_id replays from byte event_a.len()
        // and recovers event B completely without dropping its prefix.
        let mut reconnected = EventLineParser::new();
        let resumed_events = reconnected.push(resume_id, &full_stream[resume_id as usize..]);
        assert_eq!(resumed_events.len(), 1);
        let value: Value = serde_json::from_str(&resumed_events[0].1).unwrap();
        assert_eq!(value["text"], "B");
        assert_eq!(resumed_events[0].2, full_stream.len() as u64);
    }

    #[test]
    fn event_line_parser_rejects_unknown_versions_and_event_types() {
        let mut parser = EventLineParser::new();
        let bad_version = format!("{STREAM_EVENT_PREFIX}{{\"v\":2,\"t\":\"delta\"}}\n");
        let bad_type = format!("{STREAM_EVENT_PREFIX}{{\"v\":1,\"t\":\"exec\"}}\n");
        let malformed = format!("{STREAM_EVENT_PREFIX}not-json\n");
        assert!(parser.push(0, bad_version.as_bytes()).is_empty());
        assert!(parser.push(100, bad_type.as_bytes()).is_empty());
        assert!(parser.push(200, malformed.as_bytes()).is_empty());
    }

    #[test]
    fn input_validators_enforce_closed_enums_and_bounds() {
        assert_eq!(
            parse_agent_kind("claude"),
            Some(EnvironmentAgentKind::Claude)
        );
        assert_eq!(parse_agent_kind("codex"), Some(EnvironmentAgentKind::Codex));
        assert_eq!(parse_agent_kind("agy"), Some(EnvironmentAgentKind::Agy));
        assert_eq!(parse_agent_kind("bash"), None);
        assert_eq!(normalize_effort(Some("Default")), Ok(None));
        assert_eq!(normalize_effort(Some("High")), Ok(Some("high".into())));
        assert_eq!(normalize_effort(Some("xhigh")), Ok(Some("xhigh".into())));
        assert!(normalize_effort(Some("turbo")).is_err());
        assert!(valid_working_dir("/workspace"));
        assert!(!valid_working_dir("relative/path"));
        assert!(!valid_working_dir("/workspace\nrm -rf /"));
        assert!(valid_model_token("claude-sonnet-4-6"));
        assert!(!valid_model_token("bad model; rm -rf /"));
    }

    #[test]
    fn resume_offset_prefers_last_event_id_over_query() {
        let mut headers = HeaderMap::new();
        headers.insert("last-event-id", HeaderValue::from_static("4096"));
        assert_eq!(
            resume_offset(&headers, &EventsQuery { offset: Some(128) }),
            4096
        );
        assert_eq!(
            resume_offset(&HeaderMap::new(), &EventsQuery { offset: Some(128) }),
            128
        );
        assert_eq!(
            resume_offset(&HeaderMap::new(), &EventsQuery { offset: None }),
            0
        );
    }
}
